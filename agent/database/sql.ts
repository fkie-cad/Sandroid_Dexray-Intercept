import { devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { Java} from "../utils/javalib.js"
import { safePerform,safeUse, safeDeferred, safeOverload,safeImplementation, PropagateException } from "../utils/safe_java.js"
import { safeResolveExport, safeAttach, safeEnumerateModuleExports } from "../utils/safe_native.js"

/**
 * Some parts are taken from https://codeshare.frida.re/@ninjadiary/sqlite-database/
 * and https://ackcent.com/recovering-sqlcipher-encrypted-data-with-frida/
 * and https://github.com/dpnishant/appmon/blob/master/scripts/Android/Database/DB.js
 */

const PROFILE_HOOKING_TYPE: string = "DATABASE"

interface DatabaseEvent {
    event_type: string;
    database_path?: string;
    sql?: string;
    table?: string;
    method?: string;
    bind_args?: any[];
    content_values?: any;
    where_clause?: string;
    where_args?: string[];
    flags?: number;
    password?: string;
    result_code?: number;
    rows_affected?: number;
}

function createDatabaseEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function base64ToHex(base64: string): string {
    const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let buffer = 0;
    let bitCount = 0;
    let hex = "";

    for (const character of base64) {
        if (character === "=") {
            break;
        }

        const value = alphabet.indexOf(character);
        if (value < 0) {
            continue;
        }

        buffer = (buffer << 6) | value;
        bitCount += 6;

        while (bitCount >= 8) {
            bitCount -= 8;
            const byte = (buffer >> bitCount) & 0xff;
            hex += byte.toString(16).padStart(2, "0");
        }
    }

    return hex;
}

// New variables for filtering:
let PATH_FILTERS: string[] = [];
let PATH_FILTER_ENABLED: boolean = false;

// Helper: Function to check if a database path should be logged
function shouldLogDatabasePath(dbPath: string): boolean {
    // If filtering is disabled, log everything
    if (!PATH_FILTER_ENABLED) {
        return true;
    }

    // If path is unknown, log it
    if (!dbPath || dbPath === "unknown") {
        return true;
    }

    for (const filter of PATH_FILTERS) {
        // If filter contains wildcard "*", use includes method
        if (filter.includes("*")) {
            const filterPattern = filter.replace(/\*/g, "");
            if (dbPath.includes(filterPattern)) {
                return true;
            }
        }
        // Otherwise check for exact match
        else if (dbPath === filter) {
            return true;
        }
    }

    return false;
}

// Message handler to receive database filter rules sent from Python
recv("path_filters", (message) => {
    if (message.payload && message.payload.length > 0) {
        PATH_FILTERS = message.payload;
        PATH_FILTER_ENABLED = true;
    } else {
        PATH_FILTER_ENABLED = false;
    }
});

function set_airplane_mode(){
//TODO
}

export { set_airplane_mode };



function hook_java_sql() {
    safePerform("database:hook_java_sql", () => {
        const sqliteDatabase = safeUse(
            "android.database.sqlite.SQLiteDatabase",
            "database:hook_java_sql"
        );
        if (!sqliteDatabase) return;

        // Per-thread operation-depth guard prevents duplicate events when public
        // SQLiteDatabase wrapper methods delegate internally to other hooked methods.
        const Thread = safeUse(
            "java.lang.Thread",
            "database:hook_java_sql"
        );
        if (!Thread) return;

        const operationGuardDepths: Record<string, Record<string, number>> = {};

        function getCurrentThreadKey(): string {
            try {
                return (Thread as any).currentThread().getId().toString();
            } catch (_) {
                // Fallback should only be used if thread lookup unexpectedly fails.
                return "unknown";
            }
        }

        function getOperationDepth(operation: string): number {
            const threadGuards = operationGuardDepths[getCurrentThreadKey()];
            return threadGuards ? (threadGuards[operation] || 0) : 0;
        }

        function isNestedOperation(operation: string): boolean {
            return getOperationDepth(operation) > 0;
        }

        function isNestedQueryOperation(): boolean {
            return isNestedOperation("sqlite.query");
        }

        function callWithOperationGuard<T>(operation: string, fn: () => T): T {
            const threadKey = getCurrentThreadKey();

            if (!operationGuardDepths[threadKey]) {
                operationGuardDepths[threadKey] = {};
            }

            const threadGuards = operationGuardDepths[threadKey];
            threadGuards[operation] = (threadGuards[operation] || 0) + 1;

            try {
                return fn();
            } finally {
                threadGuards[operation]--;

                if (threadGuards[operation] <= 0) {
                    delete threadGuards[operation];
                }

                if (Object.keys(threadGuards).length === 0) {
                    delete operationGuardDepths[threadKey];
                }
            }
        }

        const AndroidBase64 = safeUse(
            "android.util.Base64",
            "database:hook_java_sql"
        );
        const base64Encode = AndroidBase64
            ? safeOverload(
                (AndroidBase64 as any).encodeToString,
                "database:Base64.encodeToString[byte[],int]",
                "[B",
                "int"
            )
            : null;

        function getDatabasePath(database: any): string {
            try {
                return database.getPath();
            } catch (error) {
                return `Error getting path: ${error}`;
            }
        }

        function serializeJavaValue(value: any): any {
            if (value === null || value === undefined) {
                return null;
            }

            if (
                typeof value === "string" ||
                typeof value === "number" ||
                typeof value === "boolean"
            ) {
                return value;
            }

            try {
                // ContentValues.get() has declared return type Object. Frida therefore
                // exposes returned boxed primitives as java.lang.Object wrappers even
                // when their runtime type is Integer, Double, byte[], etc.
                const runtimeClassName = value.getClass().getName().toString();
                const runtimeClass = Java.use(runtimeClassName);
                const typedValue = Java.cast(value, runtimeClass);

                switch (runtimeClassName) {
                    case "java.lang.String":
                    case "java.lang.CharSequence":
                    case "java.lang.Character":
                        return typedValue.toString();

                    case "java.lang.Boolean":
                        return typedValue.booleanValue();

                    case "java.lang.Byte":
                    case "java.lang.Short":
                    case "java.lang.Integer":
                        return typedValue.intValue();

                    case "java.lang.Long":
                        // Preserve 64-bit precision rather than coercing to JS Number.
                        return typedValue.toString();

                    case "java.lang.Float":
                    case "java.lang.Double":
                        return typedValue.doubleValue();

                    case "[B": {
                        if (!AndroidBase64 || !base64Encode) {
                            return {
                                type: "byte[]",
                                value_hex: null,
                                length: null,
                                error: "android.util.Base64 unavailable"
                            };
                        }

                        // NO_WRAP = 2. Let Android encode the real Java byte[]
                        // instead of relying on Frida JS array indexing semantics.
                        const base64 = base64Encode
                            .call(AndroidBase64, typedValue, 2)
                            .toString();

                        const valueHex = base64ToHex(base64);

                        return {
                            type: "byte[]",
                            value_hex: valueHex,
                            length: valueHex.length / 2
                        };
                    }

                    default:
                        return {
                            type: runtimeClassName,
                            value: typedValue.toString()
                        };
                }
            } catch (error) {
                return `<error serializing value: ${error}>`;
            }
        }

        function serializeJavaArray(values: any): any[] {
            if (!values) return [];

            const result: any[] = [];
            for (let index = 0; index < values.length; index++) {
                result.push(serializeJavaValue(values[index]));
            }

            return result;
        }

        function serializeContentValues(values: any): Record<string, any> {
            const contentValues: Record<string, any> = {};

            if (!values) return contentValues;

            const iterator = values.keySet().iterator();
            while (iterator.hasNext()) {
                const key = iterator.next().toString();
                contentValues[key] = serializeJavaValue(values.get(key));
            }

            return contentValues;
        }

        function emitSqliteDatabaseEvent(
            database: any,
            eventType: string,
            data: Record<string, any>
        ): void {
            const databasePath = getDatabasePath(database);

            if (!shouldLogDatabasePath(databasePath)) {
                return;
            }

            createDatabaseEvent(eventType, {
                database_path: databasePath,
                ...data
            });
        }

        function interpretDatabaseFlags(flags: number): string {
            const descriptions: string[] = [];

            // Android SQLiteDatabase: OPEN_READWRITE is zero.
            if ((flags & 0x00000001) !== 0) {
                descriptions.push("OPEN_READONLY");
            } else {
                descriptions.push("OPEN_READWRITE");
            }

            if ((flags & 0x10000000) !== 0) {
                descriptions.push("CREATE_IF_NECESSARY");
            }

            if ((flags & 0x00000010) !== 0) {
                descriptions.push("NO_LOCALIZED_COLLATORS");
            }

            if ((flags & 0x20000000) !== 0) {
                descriptions.push("ENABLE_WRITE_AHEAD_LOGGING");
            }

            return descriptions.join(" | ");
        }

        // ------------------------------------------------------------
        // execSQL
        // ------------------------------------------------------------

        const execSQL_String = safeOverload(
            sqliteDatabase.execSQL,
            "database:SQLiteDatabase.execSQL[String]",
            "java.lang.String"
        );
        if (execSQL_String) {
            execSQL_String.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String]",
                execSQL_String,
                function (original, sql: string) {
                    emitSqliteDatabaseEvent(this, "database.sqlite.exec", {
                        method: "SQLiteDatabase.execSQL(String)",
                        sql: sql
                    });

                    return original.call(this, sql);
                }
            );
        }

        const execSQL_String_ObjectArray = safeOverload(
            sqliteDatabase.execSQL,
            "database:SQLiteDatabase.execSQL[String,Object[]]",
            "java.lang.String",
            "[Ljava.lang.Object;"
        );
        if (execSQL_String_ObjectArray) {
            execSQL_String_ObjectArray.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String,Object[]]",
                execSQL_String_ObjectArray,
                function (original, sql: string, bindArgsArray: any) {
                    emitSqliteDatabaseEvent(this, "database.sqlite.exec", {
                        method: "SQLiteDatabase.execSQL(String, Object[])",
                        sql: sql,
                        bind_args: serializeJavaArray(bindArgsArray)
                    });

                    return original.call(this, sql, bindArgsArray);
                }
            );
        }

        // ------------------------------------------------------------
        // query
        // ------------------------------------------------------------

        const query_distinct_full = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String]",
            "boolean",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String"
        );
        if (query_distinct_full) {
            query_distinct_full.implementation = safeImplementation(
                "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String]",
                query_distinct_full,
                function (
                    original,
                    distinct: boolean,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string,
                    limit: string
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.query(boolean, String, String[], String, String[], String, String, String, String)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit,
                            distinct: distinct
                        });
                    }
                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            distinct,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy,
                            limit
                        )
                    );
                }
            );
        }

        const query_full = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String,String]",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String"
        );
        if (query_full) {
            query_full.implementation = safeImplementation(
                "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String,String]",
                query_full,
                function (
                    original,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string,
                    limit: string
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.query(String, String[], String, String[], String, String, String, String)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy,
                            limit
                        )
                    );
                }
            );
        }

        const query_distinct_full_cancel = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
            "boolean",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "android.os.CancellationSignal"
        );
        if (query_distinct_full_cancel) {
            query_distinct_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
                query_distinct_full_cancel,
                function (
                    original,
                    distinct: boolean,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string,
                    limit: string,
                    cancellationSignal: any
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.query(boolean, String, String[], String, String[], String, String, String, String, CancellationSignal)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit,
                            distinct: distinct,
                            cancellation_signal: cancellationSignal !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            distinct,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy,
                            limit,
                            cancellationSignal
                        )
                    );
                }
            );
        }

        const query_short = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String]",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String"
        );
        if (query_short) {
            query_short.implementation = safeImplementation(
                "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String]",
                query_short,
                function (
                    original,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.query(String, String[], String, String[], String, String, String)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy
                        )
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // queryWithFactory / rawQueryWithFactory
        // ------------------------------------------------------------

        const queryWithFactory_full = safeOverload(
            sqliteDatabase.queryWithFactory,
            "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String]",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "boolean",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String"
        );
        if (queryWithFactory_full) {
            queryWithFactory_full.implementation = safeImplementation(
                "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String]",
                queryWithFactory_full,
                function (
                    original,
                    factory: any,
                    distinct: boolean,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string,
                    limit: string
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.queryWithFactory(CursorFactory, boolean, String, String[], String, String[], String, String, String, String)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit,
                            distinct: distinct,
                            has_factory: factory !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            factory,
                            distinct,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy,
                            limit
                        )
                    );
                }
            );
        }

        const queryWithFactory_full_cancel = safeOverload(
            sqliteDatabase.queryWithFactory,
            "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "boolean",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "android.os.CancellationSignal"
        );
        if (queryWithFactory_full_cancel) {
            queryWithFactory_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
                queryWithFactory_full_cancel,
                function (
                    original,
                    factory: any,
                    distinct: boolean,
                    table: string,
                    columns: any,
                    selection: string,
                    selectionArgs: any,
                    groupBy: string,
                    having: string,
                    orderBy: string,
                    limit: string,
                    cancellationSignal: any
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.queryWithFactory(CursorFactory, boolean, String, String[], String, String[], String, String, String, String, CancellationSignal)",
                            table: table,
                            columns: serializeJavaArray(columns),
                            where_clause: selection,
                            where_args: serializeJavaArray(selectionArgs),
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit,
                            distinct: distinct,
                            has_factory: factory !== null,
                            cancellation_signal: cancellationSignal !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            factory,
                            distinct,
                            table,
                            columns,
                            selection,
                            selectionArgs,
                            groupBy,
                            having,
                            orderBy,
                            limit,
                            cancellationSignal
                        )
                    );
                }
            );
        }

        const rawQueryWithFactory_full_cancel = safeOverload(
            sqliteDatabase.rawQueryWithFactory,
            "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String,CancellationSignal]",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String",
            "android.os.CancellationSignal"
        );
        if (rawQueryWithFactory_full_cancel) {
            rawQueryWithFactory_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String,CancellationSignal]",
                rawQueryWithFactory_full_cancel,
                function (
                    original,
                    factory: any,
                    sql: string,
                    selectionArgs: any,
                    editTable: string,
                    cancellationSignal: any
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.rawQueryWithFactory(CursorFactory, String, String[], String, CancellationSignal)",
                            sql: sql,
                            where_args: serializeJavaArray(selectionArgs),
                            edit_table: editTable,
                            has_factory: factory !== null,
                            cancellation_signal: cancellationSignal !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(
                            this,
                            factory,
                            sql,
                            selectionArgs,
                            editTable,
                            cancellationSignal
                        )
                    );
                }
            );
        }

        const rawQueryWithFactory_full = safeOverload(
            sqliteDatabase.rawQueryWithFactory,
            "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String]",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String"
        );
        if (rawQueryWithFactory_full) {
            rawQueryWithFactory_full.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String]",
                rawQueryWithFactory_full,
                function (
                    original,
                    factory: any,
                    sql: string,
                    selectionArgs: any,
                    editTable: string
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.rawQueryWithFactory(CursorFactory, String, String[], String)",
                            sql: sql,
                            where_args: serializeJavaArray(selectionArgs),
                            edit_table: editTable,
                            has_factory: factory !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(this, factory, sql, selectionArgs, editTable)
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // rawQuery
        // ------------------------------------------------------------

        const rawQuery_String_StringArray = safeOverload(
            sqliteDatabase.rawQuery,
            "database:SQLiteDatabase.rawQuery[String,String[]]",
            "java.lang.String",
            "[Ljava.lang.String;"
        );
        if (rawQuery_String_StringArray) {
            rawQuery_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQuery[String,String[]]",
                rawQuery_String_StringArray,
                function (original, sql: string, selectionArgs: any) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.rawQuery(String, String[])",
                            sql: sql,
                            where_args: serializeJavaArray(selectionArgs)
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(this, sql, selectionArgs)
                    );
                }
            );
        }

        const rawQuery_String_StringArray_Cancellation = safeOverload(
            sqliteDatabase.rawQuery,
            "database:SQLiteDatabase.rawQuery[String,String[],CancellationSignal]",
            "java.lang.String",
            "[Ljava.lang.String;",
            "android.os.CancellationSignal"
        );
        if (rawQuery_String_StringArray_Cancellation) {
            rawQuery_String_StringArray_Cancellation.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQuery[String,String[],CancellationSignal]",
                rawQuery_String_StringArray_Cancellation,
                function (
                    original,
                    sql: string,
                    selectionArgs: any,
                    cancellationSignal: any
                ) {
                    if (!isNestedQueryOperation()) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.query", {
                            method: "SQLiteDatabase.rawQuery(String, String[], CancellationSignal)",
                            sql: sql,
                            where_args: serializeJavaArray(selectionArgs),
                            cancellation_signal: cancellationSignal !== null
                        });
                    }

                    return callWithOperationGuard(
                        "sqlite.query",
                        () => original.call(this, sql, selectionArgs, cancellationSignal)
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // insert
        // ------------------------------------------------------------

        const insert_String_String_ContentValues = safeOverload(
            sqliteDatabase.insert,
            "database:SQLiteDatabase.insert[String,String,ContentValues]",
            "java.lang.String",
            "java.lang.String",
            "android.content.ContentValues"
        );
        if (insert_String_String_ContentValues) {
            insert_String_String_ContentValues.implementation = safeImplementation(
                "database:SQLiteDatabase.insert[String,String,ContentValues]",
                insert_String_String_ContentValues,
                function (original, table: string, nullColumnHack: string, values: any) {
                    emitSqliteDatabaseEvent(this, "database.sqlite.insert", {
                        method: "SQLiteDatabase.insert(String, String, ContentValues)",
                        table: table,
                        null_column_hack: nullColumnHack,
                        content_values: serializeContentValues(values)
                    });

                    return callWithOperationGuard(
                        "sqlite.insert",
                        () => original.call(this, table, nullColumnHack, values)
                    );
                }
            );
        }

        const insertOrThrow_String_String_ContentValues = safeOverload(
            sqliteDatabase.insertOrThrow,
            "database:SQLiteDatabase.insertOrThrow[String,String,ContentValues]",
            "java.lang.String",
            "java.lang.String",
            "android.content.ContentValues"
        );
        if (insertOrThrow_String_String_ContentValues) {
            insertOrThrow_String_String_ContentValues.implementation = safeImplementation(
                "database:SQLiteDatabase.insertOrThrow[String,String,ContentValues]",
                insertOrThrow_String_String_ContentValues,
                function (original, table: string, nullColumnHack: string, values: any) {
                    emitSqliteDatabaseEvent(this, "database.sqlite.insert", {
                        method: "SQLiteDatabase.insertOrThrow(String, String, ContentValues)",
                        table: table,
                        null_column_hack: nullColumnHack,
                        content_values: serializeContentValues(values),
                        throw_on_error: true
                    });

                    return callWithOperationGuard(
                        "sqlite.insert",
                        () => original.call(this, table, nullColumnHack, values)
                    );
                }
            );
        }

        const insertWithOnConflict = safeOverload(
            sqliteDatabase.insertWithOnConflict,
            "database:SQLiteDatabase.insertWithOnConflict[String,String,ContentValues,int]",
            "java.lang.String",
            "java.lang.String",
            "android.content.ContentValues",
            "int"
        );
        if (insertWithOnConflict) {
            insertWithOnConflict.implementation = safeImplementation(
                "database:SQLiteDatabase.insertWithOnConflict[String,String,ContentValues,int]",
                insertWithOnConflict,
                function (
                    original,
                    table: string,
                    nullColumnHack: string,
                    values: any,
                    conflictAlgorithm: number
                ) {
                    if (!isNestedOperation("sqlite.insert")) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.insert", {
                            method: "SQLiteDatabase.insertWithOnConflict(String, String, ContentValues, int)",
                            table: table,
                            null_column_hack: nullColumnHack,
                            content_values: serializeContentValues(values),
                            conflict_algorithm: conflictAlgorithm
                        });
                    }

                    return original.call(
                        this,
                        table,
                        nullColumnHack,
                        values,
                        conflictAlgorithm
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // database open
        // ------------------------------------------------------------

        const openDatabase_String_CursorFactory_int = safeOverload(
            sqliteDatabase.openDatabase,
            "database:SQLiteDatabase.openDatabase[String,CursorFactory,int]",
            "java.lang.String",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "int"
        );
        if (openDatabase_String_CursorFactory_int) {
            openDatabase_String_CursorFactory_int.implementation = safeImplementation(
                "database:SQLiteDatabase.openDatabase[String,CursorFactory,int]",
                openDatabase_String_CursorFactory_int,
                function (original, path: string, factory: any, flags: number) {
                    if (shouldLogDatabasePath(path)) {
                        createDatabaseEvent("database.sqlite.open", {
                            method: "SQLiteDatabase.openDatabase(String, CursorFactory, int)",
                            database_path: path,
                            flags: flags,
                            flags_description: interpretDatabaseFlags(flags),
                            has_factory: factory !== null
                        });
                    }

                    return original.call(this, path, factory, flags);
                }
            );
        }

        const openDatabase_String_CursorFactory_int_ErrorHandler = safeOverload(
            sqliteDatabase.openDatabase,
            "database:SQLiteDatabase.openDatabase[String,CursorFactory,int,DatabaseErrorHandler]",
            "java.lang.String",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "int",
            "android.database.DatabaseErrorHandler"
        );
        if (openDatabase_String_CursorFactory_int_ErrorHandler) {
            openDatabase_String_CursorFactory_int_ErrorHandler.implementation = safeImplementation(
                "database:SQLiteDatabase.openDatabase[String,CursorFactory,int,DatabaseErrorHandler]",
                openDatabase_String_CursorFactory_int_ErrorHandler,
                function (
                    original,
                    path: string,
                    factory: any,
                    flags: number,
                    errorHandler: any
                ) {
                    if (shouldLogDatabasePath(path)) {
                        createDatabaseEvent("database.sqlite.open", {
                            method: "SQLiteDatabase.openDatabase(String, CursorFactory, int, DatabaseErrorHandler)",
                            database_path: path,
                            flags: flags,
                            flags_description: interpretDatabaseFlags(flags),
                            has_factory: factory !== null,
                            has_error_handler: errorHandler !== null
                        });
                    }

                    return original.call(this, path, factory, flags, errorHandler);
                }
            );
        }

        const openOrCreateDatabase_String_CursorFactory = safeOverload(
            sqliteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory]",
            "java.lang.String",
            "android.database.sqlite.SQLiteDatabase$CursorFactory"
        );
        if (openOrCreateDatabase_String_CursorFactory) {
            openOrCreateDatabase_String_CursorFactory.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory]",
                openOrCreateDatabase_String_CursorFactory,
                function (original, path: string, factory: any) {
                    if (shouldLogDatabasePath(path)) {
                        createDatabaseEvent("database.sqlite.open", {
                            method: "SQLiteDatabase.openOrCreateDatabase(String, CursorFactory)",
                            database_path: path,
                            has_factory: factory !== null,
                            create_if_necessary: true
                        });
                    }

                    return original.call(this, path, factory);
                }
            );
        }

        const openOrCreateDatabase_String_CursorFactory_ErrorHandler = safeOverload(
            sqliteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory,DatabaseErrorHandler]",
            "java.lang.String",
            "android.database.sqlite.SQLiteDatabase$CursorFactory",
            "android.database.DatabaseErrorHandler"
        );
        if (openOrCreateDatabase_String_CursorFactory_ErrorHandler) {
            openOrCreateDatabase_String_CursorFactory_ErrorHandler.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory,DatabaseErrorHandler]",
                openOrCreateDatabase_String_CursorFactory_ErrorHandler,
                function (original, path: string, factory: any, errorHandler: any) {
                    if (shouldLogDatabasePath(path)) {
                        createDatabaseEvent("database.sqlite.open", {
                            method: "SQLiteDatabase.openOrCreateDatabase(String, CursorFactory, DatabaseErrorHandler)",
                            database_path: path,
                            has_factory: factory !== null,
                            has_error_handler: errorHandler !== null,
                            create_if_necessary: true
                        });
                    }

                    return original.call(this, path, factory, errorHandler);
                }
            );
        }

        // ------------------------------------------------------------
        // update / delete
        // ------------------------------------------------------------

        const update_String_ContentValues_String_StringArray = safeOverload(
            sqliteDatabase.update,
            "database:SQLiteDatabase.update[String,ContentValues,String,String[]]",
            "java.lang.String",
            "android.content.ContentValues",
            "java.lang.String",
            "[Ljava.lang.String;"
        );
        if (update_String_ContentValues_String_StringArray) {
            update_String_ContentValues_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.update[String,ContentValues,String,String[]]",
                update_String_ContentValues_String_StringArray,
                function (
                    original,
                    table: string,
                    values: any,
                    whereClause: string,
                    whereArgs: any
                ) {
                    emitSqliteDatabaseEvent(this, "database.sqlite.update", {
                        method: "SQLiteDatabase.update(String, ContentValues, String, String[])",
                        table: table,
                        content_values: serializeContentValues(values),
                        where_clause: whereClause,
                        where_args: serializeJavaArray(whereArgs)
                    });

                    return callWithOperationGuard(
                        "sqlite.update",
                        () => original.call(this, table, values, whereClause, whereArgs)
                    );
                }
            );
        }

        const updateWithOnConflict = safeOverload(
            sqliteDatabase.updateWithOnConflict,
            "database:SQLiteDatabase.updateWithOnConflict[String,ContentValues,String,String[],int]",
            "java.lang.String",
            "android.content.ContentValues",
            "java.lang.String",
            "[Ljava.lang.String;",
            "int"
        );
        if (updateWithOnConflict) {
            updateWithOnConflict.implementation = safeImplementation(
                "database:SQLiteDatabase.updateWithOnConflict[String,ContentValues,String,String[],int]",
                updateWithOnConflict,
                function (
                    original,
                    table: string,
                    values: any,
                    whereClause: string,
                    whereArgs: any,
                    conflictAlgorithm: number
                ) {
                    if (!isNestedOperation("sqlite.update")) {
                        emitSqliteDatabaseEvent(this, "database.sqlite.update", {
                            method: "SQLiteDatabase.updateWithOnConflict(String, ContentValues, String, String[], int)",
                            table: table,
                            content_values: serializeContentValues(values),
                            where_clause: whereClause,
                            where_args: serializeJavaArray(whereArgs),
                            conflict_algorithm: conflictAlgorithm
                        });
                    }

                    return original.call(
                        this,
                        table,
                        values,
                        whereClause,
                        whereArgs,
                        conflictAlgorithm
                    );
                }
            );
        }

        const delete_String_String_StringArray = safeOverload(
            sqliteDatabase.delete,
            "database:SQLiteDatabase.delete[String,String,String[]]",
            "java.lang.String",
            "java.lang.String",
            "[Ljava.lang.String;"
        );
        if (delete_String_String_StringArray) {
            delete_String_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.delete[String,String,String[]]",
                delete_String_String_StringArray,
                function (
                    original,
                    table: string,
                    whereClause: string,
                    whereArgs: any
                ) {
                    const databasePath = getDatabasePath(this);

                    if (shouldLogDatabasePath(databasePath)) {
                        createDatabaseEvent("database.sqlite.delete", {
                            method: "SQLiteDatabase.delete(String, String, String[])",
                            database_path: databasePath,
                            table: table,
                            where_clause: whereClause,
                            where_args: serializeJavaArray(whereArgs)
                        });
                    }

                    const rowsAffected = original.call(
                        this,
                        table,
                        whereClause,
                        whereArgs
                    );

                    if (shouldLogDatabasePath(databasePath)) {
                        createDatabaseEvent("database.sqlite.delete_result", {
                            method: "SQLiteDatabase.delete(String, String, String[])",
                            database_path: databasePath,
                            table: table,
                            rows_affected: rowsAffected
                        });
                    }

                    return rowsAffected;
                }
            );
        }
    });
}

function hook_SQLCipher() {
    safePerform("database:hook_SQLCipher", () => {
        const SQLiteOpenHelper = safeUse(
            "net.sqlcipher.database.SQLiteOpenHelper",
            "database:hook_SQLCipher"
        );
        const SQLiteDatabase = safeUse(
            "net.sqlcipher.database.SQLiteDatabase",
            "database:hook_SQLCipher"
        );
        const AndroidBase64 = safeUse(
            "android.util.Base64",
            "database:hook_SQLCipher"
        );

        const JavaReflectArray = safeUse(
            "java.lang.reflect.Array",
            "database:hook_SQLCipher"
        );

        const base64Encode = AndroidBase64
            ? safeOverload(
                (AndroidBase64 as any).encodeToString,
                "database:Base64.encodeToString[byte[],int]",
                "[B",
                "int"
            )
            : null;

        // Suppress internal SQLCipher open delegation. For example, a
        // File/String/CursorFactory overload may delegate to a wider overload.
        const Thread = safeUse(
            "java.lang.Thread",
            "database:hook_SQLCipher"
        );
        if (!Thread) return;

        const openGuardDepths: Record<string, number> = {};

        function getCurrentThreadKey(): string {
            try {
                return (Thread as any).currentThread().getId().toString();
            } catch (_) {
                return "unknown";
            }
        }

        function isNestedSqlCipherOpen(): boolean {
            return (openGuardDepths[getCurrentThreadKey()] || 0) > 0;
        }

        function callWithSqlCipherOpenGuard<T>(fn: () => T): T {
            const threadKey = getCurrentThreadKey();
            openGuardDepths[threadKey] = (openGuardDepths[threadKey] || 0) + 1;

            try {
                return fn();
            } finally {
                openGuardDepths[threadKey]--;

                if (openGuardDepths[threadKey] <= 0) {
                    delete openGuardDepths[threadKey];
                }
            }
        }

        function signatureOf(overload: any): string {
            return overload.argumentTypes
                .map((arg: any) => arg.className)
                .join(", ");
        }

        function serializePassword(value: any, typeName: string): {
            value: string | null;
            type: string;
        } {
            if (value === null || value === undefined) {
                return {
                    value: null,
                    type: typeName
                };
            }

            try {
                if (typeName === "java.lang.String") {
                    return {
                        value: value.toString(),
                        type: "String"
                    };
                }

                if (typeName === "[C") {
                    if (!JavaReflectArray) {
                        return {
                            value: null,
                            type: "char[] (reflection unavailable)"
                        };
                    }

                    const length = JavaReflectArray.getLength(value);
                    let password = "";

                    for (let index = 0; index < length; index++) {
                        password += JavaReflectArray.getChar(value, index);
                    }

                    return {
                        value: password,
                        type: "char[]"
                    };
                }

                if (typeName === "[B") {
                    if (!AndroidBase64 || !base64Encode) {
                        return {
                            value: null,
                            type: "byte[] (Base64 unavailable)"
                        };
                    }

                    // android.util.Base64.NO_WRAP = 2
                    const base64 = base64Encode
                        .call(AndroidBase64, value, 2)
                        .toString();

                    return {
                        value: `hex:${base64ToHex(base64)}`,
                        type: "byte[]"
                    };
                }

                return {
                    value: value.toString(),
                    type: typeName
                };
            } catch (error) {
                return {
                    value: `<error serializing password: ${error}>`,
                    type: typeName
                };
            }
        }

        function getPath(pathArgument: any, pathType: string): string | null {
            if (pathArgument === null || pathArgument === undefined) {
                return null;
            }

            try {
                if (pathType === "java.io.File") {
                    return pathArgument.getAbsolutePath().toString();
                }

                return pathArgument.toString();
            } catch (error) {
                return `<error extracting path: ${error}>`;
            }
        }

        // ------------------------------------------------------------
        // SQLiteOpenHelper password-based opens
        // ------------------------------------------------------------

        function hookOpenHelperMethod(methodName: string, accessType: string): void {
            if (!SQLiteOpenHelper || !(SQLiteOpenHelper as any)[methodName]) {
                return;
            }

            const method = (SQLiteOpenHelper as any)[methodName];

            method.overloads.forEach((overload: any, index: number) => {
                const passwordType = overload.argumentTypes[0]?.className || "unknown";
                const signature = signatureOf(overload);
                const context =
                    `database:SQLiteOpenHelper.${methodName}[${index}]`;

                overload.implementation = safeImplementation(
                    context,
                    overload,
                    function (original, ...args: any[]) {
                        if (!isNestedSqlCipherOpen()) {
                            const password = serializePassword(args[0], passwordType);

                            createDatabaseEvent("database.sqlcipher.open", {
                                method: `SQLiteOpenHelper.${methodName}(${signature})`,
                                password: password.value,
                                password_type: password.type,
                                database_type: "SQLCipher",
                                access_type: accessType,
                                overload_signature: signature
                            });
                        }

                        return callWithSqlCipherOpenGuard(
                            () => original.apply(this, args)
                        );
                    }
                );
            });
        }

        hookOpenHelperMethod("getWritableDatabase", "writable");
        hookOpenHelperMethod("getReadableDatabase", "readable");

        if (!SQLiteDatabase) {
            return;
        }

        // ------------------------------------------------------------
        // SQLiteDatabase.openOrCreateDatabase(...)
        //
        // SQLCipher overloads vary by library version. Hook every runtime-
        // visible overload rather than hardcoding a subset.
        // ------------------------------------------------------------

        if ((SQLiteDatabase as any).openOrCreateDatabase?.overloads) {
            (SQLiteDatabase as any).openOrCreateDatabase.overloads.forEach(
                (overload: any, index: number) => {
                    const pathType = overload.argumentTypes[0]?.className || "unknown";
                    const passwordType = overload.argumentTypes[1]?.className || "unknown";
                    const signature = signatureOf(overload);
                    const context =
                        `database:SQLiteDatabase.openOrCreateDatabase[${index}]`;

                    overload.implementation = safeImplementation(
                        context,
                        overload,
                        function (original, ...args: any[]) {
                            if (!isNestedSqlCipherOpen()) {
                                const password = serializePassword(args[1], passwordType);

                                const hasFactory = args.length >= 3 && args[2] !== null;
                                const hasDatabaseHook = overload.argumentTypes.some(
                                    (arg: any, argIndex: number) =>
                                        argIndex >= 3 &&
                                        arg.className.includes("SQLiteDatabaseHook") &&
                                        args[argIndex] !== null
                                );
                                const hasErrorHandler = overload.argumentTypes.some(
                                    (arg: any, argIndex: number) =>
                                        arg.className.includes("DatabaseErrorHandler") &&
                                        args[argIndex] !== null
                                );

                                createDatabaseEvent("database.sqlcipher.open", {
                                    method: `SQLiteDatabase.openOrCreateDatabase(${signature})`,
                                    database_path: getPath(args[0], pathType),
                                    password: password.value,
                                    password_type: password.type,
                                    database_type: "SQLCipher",
                                    create_if_necessary: true,
                                    has_factory: hasFactory,
                                    has_database_hook: hasDatabaseHook,
                                    has_error_handler: hasErrorHandler,
                                    overload_signature: signature
                                });
                            }

                            return callWithSqlCipherOpenGuard(
                                () => original.apply(this, args)
                            );
                        }
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // SQL execution
        //
        // Keep PRAGMA key detection in this hook. Do not install another
        // implementation from hook_room_library(), otherwise it overwrites
        // this general execSQL hook.
        // ------------------------------------------------------------

        const execSQL = safeOverload(
            (SQLiteDatabase as any).execSQL,
            "database:SQLiteDatabase.execSQL[String]_SQLCipher",
            "java.lang.String"
        );
        if (execSQL) {
            execSQL.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String]_SQLCipher",
                execSQL,
                function (original, sql: string) {
                    const isPragmaKey =
                        sql !== null &&
                        sql.toLowerCase().includes("pragma key");

                    createDatabaseEvent(
                        isPragmaKey
                            ? "database.sqlcipher.pragma"
                            : "database.sqlcipher.exec",
                        {
                            method: "SQLiteDatabase.execSQL(String)",
                            sql: sql,
                            pragma_type: isPragmaKey ? "key" : null,
                            database_type: "SQLCipher"
                        }
                    );

                    try {
                        return original.call(this, sql);
                    } catch (error) {
                        // Preserve the application's expected SQLiteException without
                        // safeImplementation logging it as a hook failure or retrying it.
                        throw new PropagateException(error);
                    }
                }
            );
        }

        const rawExecSQL = safeOverload(
            (SQLiteDatabase as any).rawExecSQL,
            "database:SQLiteDatabase.rawExecSQL[String]",
            "java.lang.String"
        );
        if (rawExecSQL) {
            rawExecSQL.implementation = safeImplementation(
                "database:SQLiteDatabase.rawExecSQL[String]",
                rawExecSQL,
                function (original, sql: string) {
                    createDatabaseEvent("database.sqlcipher.exec", {
                        method: "SQLiteDatabase.rawExecSQL(String)",
                        sql: sql,
                        database_type: "SQLCipher"
                    });

                    return original.call(this, sql);
                }
            );
        }

        // ------------------------------------------------------------
        // Lifecycle and transaction methods
        // ------------------------------------------------------------

        const close = safeOverload(
            (SQLiteDatabase as any).close,
            "database:SQLiteDatabase.close"
        );
        if (close) {
            close.implementation = safeImplementation(
                "database:SQLiteDatabase.close",
                close,
                function (original) {
                    let databasePath: string | null = null;

                    try {
                        databasePath = this.getPath().toString();
                    } catch (_) {
                        // Path is optional for close events.
                    }

                    createDatabaseEvent("database.sqlcipher.close", {
                        method: "SQLiteDatabase.close()",
                        database_path: databasePath,
                        database_type: "SQLCipher"
                    });

                    return original.call(this);
                }
            );
        }

        function hookTransactionMethod(
            methodName: string,
            transactionAction: string
        ): void {
            const method = safeOverload(
                (SQLiteDatabase as any)[methodName],
                `database:SQLiteDatabase.${methodName}`
            );
            if (!method) {
                return;
            }

            method.implementation = safeImplementation(
                `database:SQLiteDatabase.${methodName}`,
                method,
                function (original) {
                    let databasePath: string | null = null;

                    try {
                        databasePath = this.getPath().toString();
                    } catch (_) {
                        // Path is optional for transaction events.
                    }

                    createDatabaseEvent("database.sqlcipher.transaction", {
                        method: `SQLiteDatabase.${methodName}()`,
                        database_path: databasePath,
                        database_type: "SQLCipher",
                        transaction_action: transactionAction
                    });

                    return original.call(this);
                }
            );
        }

        hookTransactionMethod("beginTransaction", "begin");
        hookTransactionMethod("setTransactionSuccessful", "successful");
        hookTransactionMethod("endTransaction", "end");
    });
}


function hook_sql_related_stuff(){

}

function hook_room_library() {
    safePerform("database:hook_room_library", () => {

        const Room = safeUse(
            "androidx.room.Room",
            "database:hook_room_library"
        );
        const RoomDatabase = safeUse(
            "androidx.room.RoomDatabase",
            "database:hook_room_library"
        );
        const RoomOpenHelper = safeUse(
            "androidx.room.RoomOpenHelper",
            "database:hook_room_library"
        );
        const CoroutinesRoom = safeUse(
            "androidx.room.CoroutinesRoom",
            "database:hook_room_library"
        );
        const LiveData = safeUse(
            "androidx.lifecycle.LiveData",
            "database:hook_room_library"
        );

        const SupportSQLiteQuery = safeUse(
            "androidx.sqlite.db.SupportSQLiteQuery",
            "database:hook_room_library"
        );
        const SupportSQLiteProgram = safeUse(
            "androidx.sqlite.db.SupportSQLiteProgram",
            "database:hook_room_library"
        );

        function signatureOf(overload: any): string {
            return overload.argumentTypes
                .map((argument: any) => argument.className)
                .join(", ");
        }

        function getSupportDatabasePath(database: any): string | null {
            try {
                return database.getPath().toString();
            } catch (_) {
                return null;
            }
        }

        function getRoomDatabasePath(database: any): string | null {
            try {
                // SupportSQLiteOpenHelper exposes getWritableDatabase(), not
                // getDatabase(). The Room database is already open by the
                // time query/transaction/Flow hooks execute.
                const supportDatabase =
                    database.getOpenHelper().getWritableDatabase();

                return getSupportDatabasePath(supportDatabase);
            } catch (_) {
                return null;
            }
        }

        // Suppress internal delegation between RoomDatabase.query overloads.
        const Thread = safeUse(
            "java.lang.Thread",
            "database:hook_room_library"
        );
        if (!Thread) return;

        const roomQueryGuardDepths: Record<string, number> = {};

        function getCurrentThreadKey(): string {
            try {
                return (Thread as any).currentThread().getId().toString();
            } catch (_) {
                return "unknown";
            }
        }

        function isNestedRoomQuery(): boolean {
            return (roomQueryGuardDepths[getCurrentThreadKey()] || 0) > 0;
        }

        function callWithRoomQueryGuard<T>(fn: () => T): T {
            const threadKey = getCurrentThreadKey();
            roomQueryGuardDepths[threadKey] =
                (roomQueryGuardDepths[threadKey] || 0) + 1;

            try {
                return fn();
            } finally {
                roomQueryGuardDepths[threadKey]--;

                if (roomQueryGuardDepths[threadKey] <= 0) {
                    delete roomQueryGuardDepths[threadKey];
                }
            }
        }

        function serializeRoomValue(value: any): any {
            if (value === null || value === undefined) {
                return null;
            }

            if (
                typeof value === "string" ||
                typeof value === "number" ||
                typeof value === "boolean"
            ) {
                return value;
            }

            try {
                const className = value.getClass().getName().toString();
                const typedValue = Java.cast(value, Java.use(className));

                switch (className) {
                    case "java.lang.String":
                    case "java.lang.CharSequence":
                    case "java.lang.Character":
                        return typedValue.toString();

                    case "java.lang.Boolean":
                        return typedValue.booleanValue();

                    case "java.lang.Byte":
                    case "java.lang.Short":
                    case "java.lang.Integer":
                        return typedValue.intValue();

                    case "java.lang.Long":
                        return typedValue.toString();

                    case "java.lang.Float":
                    case "java.lang.Double":
                        return typedValue.doubleValue();

                    default:
                        return {
                            type: className,
                            value: typedValue.toString()
                        };
                }
            } catch (error) {
                return `<error serializing value: ${error}>`;
            }
        }

        function serializeRoomArray(values: any): any[] {
            if (!values) {
                return [];
            }

            try {
                const result: any[] = [];

                for (let index = 0; index < values.length; index++) {
                    result.push(serializeRoomValue(values[index]));
                }

                return result;
            } catch (_) {
                return [];
            }
        }

        let activeRoomBindArgs: any[] | null = null;
        let roomBindRecorder: any | null = null;

        function recordRoomBind(index: number, value: any): void {
            if (!activeRoomBindArgs || index < 1) {
                return;
            }

            activeRoomBindArgs[index - 1] = value;
        }

        if (SupportSQLiteProgram) {
            try {
                const RoomBindRecorder = (Java as any).registerClass({
                    name: "com.dexray.intercept.RoomBindRecorder",
                    implements: [SupportSQLiteProgram],
                    methods: {
                        bindNull: function (index: number): void {
                            recordRoomBind(index, null);
                        },

                        bindLong: function (index: number, value: any): void {
                            const decimalValue = value.toString();
                            const numericValue = Number(decimalValue);

                            // Preserve precision for values outside JavaScript's
                            // safe-integer range; otherwise emit a JSON number.
                            recordRoomBind(
                                index,
                                Number.isSafeInteger(numericValue)
                                    ? numericValue
                                    : decimalValue
                            );
                        },

                        bindDouble: function (index: number, value: any): void {
                            recordRoomBind(index, Number(value));
                        },

                        bindString: function (index: number, value: any): void {
                            recordRoomBind(
                                index,
                                value !== null ? value.toString() : null
                            );
                        },

                        bindBlob: function (index: number, value: any): void {
                            recordRoomBind(index, serializeRoomValue(value));
                        },

                        clearBindings: function (): void {
                            // bindTo() may call this before adding values.
                        },

                        close: function (): void {
                            // No native resource is held by this recorder.
                        }
                    }
                });

                roomBindRecorder = RoomBindRecorder.$new();
            } catch (error) {
                devlog(
                    `[HOOK] Failed to create Room bind recorder: ${error}`
                );
            }
        }

        function getSupportSQLiteQueryBindArgs(query: any): any[] {
            if (!query || !SupportSQLiteQuery || !roomBindRecorder) {
                return [];
            }

            const result: any[] = [];
            const previousCollector = activeRoomBindArgs;
            activeRoomBindArgs = result;

            try {
                // Public SupportSQLiteQuery API. Works for SimpleSQLiteQuery
                // and custom implementations without relying on private fields.
                const typedQuery = Java.cast(query, SupportSQLiteQuery);
                typedQuery.bindTo(roomBindRecorder);
                return result;
            } catch (_) {
                return [];
            } finally {
                activeRoomBindArgs = previousCollector;
            }
        }

        function serializeTableNames(tableNames: any): string[] {
            if (!tableNames) {
                return [];
            }

            const result: string[] = [];

            for (let index = 0; index < tableNames.length; index++) {
                result.push(tableNames[index].toString());
            }

            return result;
        }

        // ------------------------------------------------------------
        // Room.databaseBuilder(...)
        // ------------------------------------------------------------

        if (Room && (Room as any).databaseBuilder?.overloads) {
            (Room as any).databaseBuilder.overloads.forEach(
                (overload: any, index: number) => {
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:Room.databaseBuilder[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            const databaseClass = args.length > 1 && args[1]
                                ? args[1].toString()
                                : null;
                            const databaseName = args.length > 2 && args[2]
                                ? args[2].toString()
                                : null;

                            createDatabaseEvent("database.room.builder", {
                                method: `Room.databaseBuilder(${signature})`,
                                database_name: databaseName,
                                database_class: databaseClass,
                                database_type: "Room",
                                overload_signature: signature
                            });

                            return original.apply(this, args);
                        }
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // RoomDatabase.query(...)
        // ------------------------------------------------------------

        if (RoomDatabase && (RoomDatabase as any).query?.overloads) {
            (RoomDatabase as any).query.overloads.forEach(
                (overload: any, index: number) => {
                    const argumentTypes = overload.argumentTypes;
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:RoomDatabase.query[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            const firstType = argumentTypes[0]?.className;
                            const hasCancellationSignal = argumentTypes.some(
                                (argument: any) =>
                                    argument.className === "android.os.CancellationSignal"
                            );

                            if (!isNestedRoomQuery()) {
                                let sql: string | null = null;
                                let bindArgs: any[] = [];

                                try {
                                    if (
                                        firstType ===
                                        "androidx.sqlite.db.SupportSQLiteQuery"
                                    ) {
                                        sql = args[0]
                                            ? args[0].getSql().toString()
                                            : null;

                                        bindArgs = getSupportSQLiteQueryBindArgs(
                                            args[0]
                                        );
                                    } else if (firstType === "java.lang.String") {
                                        sql = args[0] ? args[0].toString() : null;
                                        bindArgs = serializeRoomArray(args[1]);
                                    }
                                } catch (error) {
                                    sql = `<error extracting Room query: ${error}>`;
                                }

                                createDatabaseEvent("database.room.query", {
                                    method: `RoomDatabase.query(${signature})`,
                                    database_path: getRoomDatabasePath(this),
                                    database_type: "Room",
                                    sql: sql,
                                    bind_args: bindArgs,
                                    cancellation_signal: hasCancellationSignal &&
                                        args[args.length - 1] !== null,
                                    query_type: firstType ===
                                        "androidx.sqlite.db.SupportSQLiteQuery"
                                        ? "SupportSQLiteQuery"
                                        : "String,Object[]",
                                    overload_signature: signature
                                });
                            }

                            return callWithRoomQueryGuard(
                                () => original.apply(this, args)
                            );
                        }
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // RoomDatabase transaction lifecycle
        // ------------------------------------------------------------

        function hookRoomTransactionMethod(
            methodName: string,
            transactionAction: string
        ): void {
            if (!RoomDatabase || !(RoomDatabase as any)[methodName]?.overloads) {
                return;
            }

            (RoomDatabase as any)[methodName].overloads.forEach(
                (overload: any, index: number) => {
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:RoomDatabase.${methodName}[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            createDatabaseEvent("database.room.transaction", {
                                method: `RoomDatabase.${methodName}(${signature})`,
                                database_path: getRoomDatabasePath(this),
                                database_type: "Room",
                                transaction_action: transactionAction,
                                overload_signature: signature
                            });

                            return original.apply(this, args);
                        }
                    );
                }
            );
        }

        hookRoomTransactionMethod("beginTransaction", "begin");
        hookRoomTransactionMethod("setTransactionSuccessful", "successful");
        hookRoomTransactionMethod("endTransaction", "end");

        // ------------------------------------------------------------
        // Room Flow creation
        // ------------------------------------------------------------

        if (CoroutinesRoom && (CoroutinesRoom as any).createFlow?.overloads) {
            (CoroutinesRoom as any).createFlow.overloads.forEach(
                (overload: any, index: number) => {
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:CoroutinesRoom.createFlow[${index}]`,
                        overload,
                        function (
                            original,
                            roomDatabase: any,
                            inTransaction: boolean,
                            tableNames: any,
                            callable: any
                        ) {
                            createDatabaseEvent("database.room.flow_created", {
                                method: `CoroutinesRoom.createFlow(${signature})`,
                                database_path: getRoomDatabasePath(roomDatabase),
                                database_type: "Room",
                                table_names: serializeTableNames(tableNames),
                                in_transaction: inTransaction,
                                has_callable: callable !== null,
                                overload_signature: signature
                            });

                            return original.call(
                                this,
                                roomDatabase,
                                inTransaction,
                                tableNames,
                                callable
                            );
                        }
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // LiveData observation
        // ------------------------------------------------------------

        function getRuntimeClassName(value: any): string | null {
            if (!value) {
                return null;
            }

            try {
                return value.getClass().getName().toString();
            } catch (_) {
                try {
                    return value.$className || null;
                } catch (_) {
                    return null;
                }
            }
        }

        if (LiveData && (LiveData as any).observe?.overloads) {
            (LiveData as any).observe.overloads.forEach(
                (overload: any, index: number) => {
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:LiveData.observe[${index}]`,
                        overload,
                        function (original, owner: any, observer: any) {
                            const ownerClass = getRuntimeClassName(owner);
                            const observerClass = getRuntimeClassName(observer);

                            createDatabaseEvent("database.room.observe", {
                                method: `LiveData.observe(${signature})`,
                                database_type: "Room",
                                owner_class: ownerClass,
                                observer_class: observerClass,
                                overload_signature: signature
                            });

                            return original.call(this, owner, observer);
                        }
                    );
                }
            );
        }

        // ------------------------------------------------------------
        // Concrete Room lifecycle callbacks
        // ------------------------------------------------------------

        function hookRoomOpenHelperMethod(
            methodName: string,
            callbackType: string
        ): void {
            if (!RoomOpenHelper || !(RoomOpenHelper as any)[methodName]?.overloads) {
                return;
            }

            (RoomOpenHelper as any)[methodName].overloads.forEach(
                (overload: any, index: number) => {
                    const signature = signatureOf(overload);

                    overload.implementation = safeImplementation(
                        `database:RoomOpenHelper.${methodName}[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            const supportDatabase = args[0];
                            const oldVersion = methodName === "onUpgrade"
                                ? args[1]
                                : null;
                            const newVersion = methodName === "onUpgrade"
                                ? args[2]
                                : null;

                            createDatabaseEvent("database.room.callback", {
                                method: `RoomOpenHelper.${methodName}(${signature})`,
                                database_path: getSupportDatabasePath(supportDatabase),
                                database_type: "Room",
                                callback_type: callbackType,
                                old_version: oldVersion,
                                new_version: newVersion,
                                overload_signature: signature
                            });

                            return original.apply(this, args);
                        }
                    );
                }
            );
        }

        hookRoomOpenHelperMethod("onCreate", "onCreate");
        hookRoomOpenHelperMethod("onOpen", "onOpen");
        hookRoomOpenHelperMethod("onUpgrade", "onUpgrade");
    });
}

const hookedNativeSQLiteModules = new Set<string>();
let nativeSQLiteModuleObserverInstalled = false;

function hook_native_sqlite() {
    devlog("Installing native SQLite hooks");

    const MAX_NATIVE_BLOB_PREVIEW_BYTES = 4096;

    function hasSQLiteLikeName(module: any): boolean {
        return module.name.toLowerCase().includes("sqlite");
    }

    function getSQLiteExportNames(module: any): Set<string> {
        const exports = safeEnumerateModuleExports(
            module.name,
            `database:native:${module.name}`
        );

        return new Set(
            exports
                .filter(
                    (entry: any) =>
                        entry.type === "function" &&
                        entry.name.startsWith("sqlite3_")
                )
                .map((entry: any) => entry.name)
        );
    }

    function readUtf8(pointer: NativePointer, length?: number): string | null {
        if (!pointer || pointer.isNull()) {
            return null;
        }

        if (length !== undefined && length >= 0) {
            return pointer.readUtf8String(length);
        }

        return pointer.readUtf8String();
    }

    function readUtf16(pointer: NativePointer, byteLength?: number): string | null {
        if (!pointer || pointer.isNull()) {
            return null;
        }

        if (byteLength !== undefined && byteLength >= 0) {
            // Frida expects UTF-16 character count, SQLite reports byte count.
            return pointer.readUtf16String(Math.floor(byteLength / 2));
        }

        return pointer.readUtf16String();
    }

    function readBlob(pointer: NativePointer, originalLength: number): {
        value_hex: string | null;
        preview_length: number;
        truncated: boolean;
    } {
        if (!pointer || pointer.isNull() || originalLength <= 0) {
            return {
                value_hex: "",
                preview_length: 0,
                truncated: false
            };
        }

        const previewLength = Math.min(
            originalLength,
            MAX_NATIVE_BLOB_PREVIEW_BYTES
        );

        const bytes = pointer.readByteArray(previewLength) as ArrayBuffer | null;
        const valueHex = bytes
            ? bytesToHex(new Uint8Array(bytes))
            : null;

        return {
            value_hex: valueHex,
            preview_length: previewLength,
            truncated: originalLength > previewLength
        };
    }

    function readSignedInt64Argument(value: NativePointer): {
        value: string | null;
        value_available: boolean;
    } {
        // On 32-bit ABIs sqlite3_int64 may be split across registers/stack.
        // The generic Frida args[] representation is not sufficient to recover
        // it safely without ABI-specific handling.
        if (Process.pointerSize !== 8 || typeof BigInt !== "function") {
            return {
                value: null,
                value_available: false
            };
        }

        try {
            // NativePointer.toString() provides the raw 64-bit argument bits as
            // hexadecimal, e.g. 0xffffffffffffffff for -1.
            const rawBits = BigInt(value.toString());

            // Interpret the raw argument bits as a signed two's-complement int64.
            return {
                value: BigInt.asIntN(64, rawBits).toString(),
                value_available: true
            };
        } catch (_) {
            return {
                value: null,
                value_available: false
            };
        }
    }

    function installSQLiteModuleHooks(
        module: any,
        sqliteExportNames: Set<string>
    ): void {
        const moduleKey = `${module.name}@${module.base}`;

        if (hookedNativeSQLiteModules.has(moduleKey)) {
            return;
        }

        hookedNativeSQLiteModules.add(moduleKey);
        devlog(`Hooking SQLite functions in ${module.name}`);

        function hookFunction(
            functionName: string,
            callback: (address: NativePointer) => void
        ): void {
            if (!sqliteExportNames.has(functionName)) {
                return;
            }

            const address = safeResolveExport(
                module.name,
                functionName,
                `database:native:${module.name}`
            );

            if (!address) {
                devlog(
                    `Native SQLite export unavailable: ${module.name}!${functionName}`
                );
                return;
            }

            devlog(
                `Installing native SQLite hook: ${module.name}!${functionName}`
            );
            callback(address);
        }

        // sqlite3_open / sqlite3_open_v2 use UTF-8 paths.
        ["sqlite3_open", "sqlite3_open_v2"].forEach((functionName) => {
            hookFunction(functionName, (address) => {
                safeAttach(address, `database:${module.name}:${functionName}`, {
                    onEnter(args) {
                        this.databasePath = readUtf8(args[0]);
                    },

                    onLeave(retval) {
                        const resultCode = retval.toInt32();

                        createDatabaseEvent("database.native.open", {
                            method: functionName,
                            native_function: functionName,
                            module_name: module.name,
                            architecture: Process.arch,
                            database_path: this.databasePath || null,
                            result_code: resultCode,
                            status: resultCode === 0
                                ? "success"
                                : `error code ${resultCode}`,
                            database_type: "Native SQLite"
                        });
                    }
                });
            });
        });

        // sqlite3_open16 uses a UTF-16 path.
        hookFunction("sqlite3_open16", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_open16`, {
                onEnter(args) {
                    this.databasePath = readUtf16(args[0]);
                },

                onLeave(retval) {
                    const resultCode = retval.toInt32();

                    createDatabaseEvent("database.native.open", {
                        method: "sqlite3_open16",
                        native_function: "sqlite3_open16",
                        module_name: module.name,
                        architecture: Process.arch,
                        database_path: this.databasePath || null,
                        result_code: resultCode,
                        status: resultCode === 0
                            ? "success"
                            : `error code ${resultCode}`,
                        database_type: "Native SQLite",
                        sql_encoding: "utf16"
                    });
                }
            });
        });

        hookFunction("sqlite3_exec", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_exec`, {
                onEnter(args) {
                    createDatabaseEvent("database.native.exec", {
                        method: "sqlite3_exec",
                        native_function: "sqlite3_exec",
                        module_name: module.name,
                        architecture: Process.arch,
                        statement_handle: args[0].toString(),
                        sql: readUtf8(args[1]),
                        database_type: "Native SQLite"
                    });
                }
            });
        });

        const utf8PrepareFunctions = [
            "sqlite3_prepare",
            "sqlite3_prepare_v2",
            "sqlite3_prepare_v3"
        ];

        utf8PrepareFunctions.forEach((functionName) => {
            hookFunction(functionName, (address) => {
                safeAttach(address, `database:${module.name}:${functionName}`, {
                    onEnter(args) {
                        const byteLength = args[2].toInt32();
                        this.sql = readUtf8(args[1], byteLength);
                    },

                    onLeave(retval) {
                        const resultCode = retval.toInt32();

                        createDatabaseEvent("database.native.prepare", {
                            method: functionName,
                            native_function: functionName,
                            module_name: module.name,
                            architecture: Process.arch,
                            sql: this.sql || null,
                            sql_encoding: "utf8",
                            result_code: resultCode,
                            status: resultCode === 0
                                ? "success"
                                : `error code ${resultCode}`,
                            database_type: "Native SQLite"
                        });
                    }
                });
            });
        });

        const utf16PrepareFunctions = [
            "sqlite3_prepare16",
            "sqlite3_prepare16_v2",
            "sqlite3_prepare16_v3"
        ];

        utf16PrepareFunctions.forEach((functionName) => {
            hookFunction(functionName, (address) => {
                safeAttach(address, `database:${module.name}:${functionName}`, {
                    onEnter(args) {
                        const byteLength = args[2].toInt32();
                        this.sql = readUtf16(args[1], byteLength);
                    },

                    onLeave(retval) {
                        const resultCode = retval.toInt32();

                        createDatabaseEvent("database.native.prepare", {
                            method: functionName,
                            native_function: functionName,
                            module_name: module.name,
                            architecture: Process.arch,
                            sql: this.sql || null,
                            sql_encoding: "utf16",
                            result_code: resultCode,
                            status: resultCode === 0
                                ? "success"
                                : `error code ${resultCode}`,
                            database_type: "Native SQLite"
                        });
                    }
                });
            });
        });

        hookFunction("sqlite3_step", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_step`, {
                onEnter(args) {
                    this.statementHandle = args[0].toString();
                },

                onLeave(retval) {
                    const resultCode = retval.toInt32();

                    let status = "unknown";
                    if (resultCode === 100) {
                        status = "row available";
                    } else if (resultCode === 101) {
                        status = "completed";
                    } else {
                        status = `error code ${resultCode}`;
                    }

                    createDatabaseEvent("database.native.step", {
                        method: "sqlite3_step",
                        native_function: "sqlite3_step",
                        module_name: module.name,
                        architecture: Process.arch,
                        statement_handle: this.statementHandle,
                        result_code: resultCode,
                        status: status,
                        database_type: "Native SQLite"
                    });
                }
            });
        });

        ["sqlite3_close", "sqlite3_close_v2"].forEach((functionName) => {
            hookFunction(functionName, (address) => {
                safeAttach(address, `database:${module.name}:${functionName}`, {
                    onEnter(args) {
                        this.databaseHandle = args[0].toString();
                    },

                    onLeave(retval) {
                        const resultCode = retval.toInt32();

                        createDatabaseEvent("database.native.close", {
                            method: functionName,
                            native_function: functionName,
                            module_name: module.name,
                            architecture: Process.arch,
                            statement_handle: this.databaseHandle,
                            result_code: resultCode,
                            status: resultCode === 0
                                ? "success"
                                : `error code ${resultCode}`,
                            database_type: "Native SQLite"
                        });
                    }
                });
            });
        });

        function emitBindEvent(
            functionName: string,
            args: InvocationArguments,
            data: Record<string, any>
        ): void {
            createDatabaseEvent("database.native.bind", {
                method: functionName,
                native_function: functionName,
                module_name: module.name,
                architecture: Process.arch,
                statement_handle: args[0].toString(),
                bind_index: args[1].toInt32(),
                database_type: "Native SQLite",
                ...data
            });
        }

        hookFunction("sqlite3_bind_text", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_text`, {
                onEnter(args) {
                    const byteLength = args[3].toInt32();

                    emitBindEvent("sqlite3_bind_text", args, {
                        bind_type: "text",
                        bind_value: readUtf8(args[2], byteLength),
                        bind_value_length: byteLength >= 0 ? byteLength : null,
                        value_available: true
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_text16", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_text16`, {
                onEnter(args) {
                    const byteLength = args[3].toInt32();

                    emitBindEvent("sqlite3_bind_text16", args, {
                        bind_type: "text_utf16",
                        bind_value: readUtf16(args[2], byteLength),
                        bind_value_length: byteLength >= 0 ? byteLength : null,
                        value_available: true
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_blob", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_blob`, {
                onEnter(args) {
                    const originalLength = args[3].toInt32();
                    const blob = readBlob(args[2], originalLength);

                    emitBindEvent("sqlite3_bind_blob", args, {
                        bind_type: "blob",
                        bind_value_hex: blob.value_hex,
                        bind_value_length: originalLength,
                        bind_value_preview_length: blob.preview_length,
                        bind_value_truncated: blob.truncated,
                        value_available: blob.value_hex !== null
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_int", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_int`, {
                onEnter(args) {
                    emitBindEvent("sqlite3_bind_int", args, {
                        bind_type: "int",
                        bind_value: args[2].toInt32(),
                        value_available: true
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_int64", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_int64`, {
                onEnter(args) {
                    // NativePointer string retains all 64 argument bits without
                    // truncating through JavaScript's Number representation.
                    const bindValue = readSignedInt64Argument(args[2]);

                    emitBindEvent("sqlite3_bind_int64", args, {
                        bind_type: "int64",
                        bind_value: bindValue.value,
                        value_available: bindValue.value_available
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_double", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_double`, {
                onEnter(args) {
                    let bindValue: number | null = null;
                    let valueAvailable = false;

                    // ARM64 ABI passes the third floating-point argument in d0.
                    // x86/x64 SIMD state is not exposed by Frida's Android
                    // InvocationContext on tested devices, so report unavailable
                    // rather than reading the incorrect args[2] pointer value.
                    if (
                        Process.arch === "arm64" &&
                        (this.context as any).d0 !== undefined
                    ) {
                        bindValue = Number((this.context as any).d0);
                        valueAvailable = Number.isFinite(bindValue);
                    }

                    emitBindEvent("sqlite3_bind_double", args, {
                        bind_type: "double",
                        bind_value: bindValue,
                        value_available: valueAvailable
                    });
                }
            });
        });

        hookFunction("sqlite3_bind_null", (address) => {
            safeAttach(address, `database:${module.name}:sqlite3_bind_null`, {
                onEnter(args) {
                    emitBindEvent("sqlite3_bind_null", args, {
                        bind_type: "null",
                        bind_value: null,
                        value_available: true
                    });
                }
            });
        });
    }

    function inspectAndInstallSQLiteModuleHooks(module: any): void {
        const sqliteExportNames = getSQLiteExportNames(module);

        if (sqliteExportNames.size === 0) {
            return;
        }

        devlog(
            `Detected ${sqliteExportNames.size} SQLite exports in ${module.name}`
        );

        installSQLiteModuleHooks(module, sqliteExportNames);
    }

    function scheduleSQLiteModuleInspection(module: any): void {
        // Export enumeration and hook installation must not happen directly from
        // Process.attachModuleObserver().onAdded(), as that executes in Android's
        // loader path and may deadlock against linker internals.
        setImmediate(() => {
            try {
                inspectAndInstallSQLiteModuleHooks(module);
            } catch (error) {
                devlog(
                    `[HOOK] Failed to inspect SQLite exports in ${module.name}: ${error}`
                );
            }
        });
    }

    // Prioritize modules whose names already identify them as SQLite-related.
    // They are inspected synchronously because agent installation is not running
    // inside the linker callback.
    const existingModules = Process.enumerateModules();

    existingModules
        .filter(hasSQLiteLikeName)
        .forEach(inspectAndInstallSQLiteModuleHooks);

    // Also discover statically linked SQLite in arbitrary already-loaded modules.
    // This is deferred to keep initial hook installation responsive.
    existingModules
        .filter((module) => !hasSQLiteLikeName(module))
        .forEach(scheduleSQLiteModuleInspection);

    // Inspect every future module by exports, not just by filename. This detects
    // statically linked SQLite copies in arbitrary application library names.
    if (
        !nativeSQLiteModuleObserverInstalled &&
        typeof (Process as any).attachModuleObserver === "function"
    ) {
        nativeSQLiteModuleObserverInstalled = true;

        (Process as any).attachModuleObserver({
            onAdded(module: any) {
                scheduleSQLiteModuleInspection(module);
            },

            onRemoved(module: any) {
                hookedNativeSQLiteModules.delete(`${module.name}@${module.base}`);
            }
        });
    } else if (!nativeSQLiteModuleObserverInstalled) {
        devlog(
            "Native SQLite module observer unavailable; late-loaded SQLite modules will not be hooked"
        );
    }
}

function hook_wcdb() {
    safePerform("database:hook_wcdb", () => {
        const wcdbDatabase = safeUse(
            "com.tencent.wcdb.database.SQLiteDatabase",
            "database:hook_wcdb"
        );
        if (!wcdbDatabase) {
            return;
        }

        const AndroidBase64 = safeUse(
            "android.util.Base64",
            "database:hook_wcdb"
        );

        const base64Encode = AndroidBase64
            ? safeOverload(
                (AndroidBase64 as any).encodeToString,
                "database:WCDB.Base64.encodeToString[byte[],int]",
                "[B",
                "int"
            )
            : null;

        const Thread = safeUse(
            "java.lang.Thread",
            "database:hook_wcdb"
        );
        if (!Thread) {
            return;
        }

        devlog("WCDB hooks being installed");

        // Suppress internal delegation between WCDB open overloads.
        const openGuardDepths: Record<string, number> = {};

        function getCurrentThreadKey(): string {
            try {
                return (Thread as any).currentThread().getId().toString();
            } catch (_) {
                return "unknown";
            }
        }

        function isNestedOpen(): boolean {
            return (openGuardDepths[getCurrentThreadKey()] || 0) > 0;
        }

        function callWithOpenGuard<T>(fn: () => T): T {
            const threadKey = getCurrentThreadKey();
            openGuardDepths[threadKey] = (openGuardDepths[threadKey] || 0) + 1;

            try {
                return fn();
            } finally {
                openGuardDepths[threadKey]--;

                if (openGuardDepths[threadKey] <= 0) {
                    delete openGuardDepths[threadKey];
                }
            }
        }

        // Suppress internal transaction delegation, e.g.
        // beginTransaction() -> beginTransaction(listener, exclusive).
        const transactionGuardDepths: Record<string, number> = {};

        function isNestedTransaction(): boolean {
            return (transactionGuardDepths[getCurrentThreadKey()] || 0) > 0;
        }

        function callWithTransactionGuard<T>(fn: () => T): T {
            const threadKey = getCurrentThreadKey();
            transactionGuardDepths[threadKey] =
                (transactionGuardDepths[threadKey] || 0) + 1;

            try {
                return fn();
            } finally {
                transactionGuardDepths[threadKey]--;

                if (transactionGuardDepths[threadKey] <= 0) {
                    delete transactionGuardDepths[threadKey];
                }
            }
        }

        function signatureOf(overload: any): string {
            return overload.argumentTypes
                .map((argument: any) => argument.className)
                .join(", ");
        }

        function getDatabasePath(database: any): string {
            try {
                return database.getPath().toString();
            } catch (error) {
                return `<error getting path: ${error}>`;
            }
        }

        function getPathArgument(value: any, typeName: string): string | null {
            if (value === null || value === undefined) {
                return null;
            }

            try {
                if (typeName === "java.io.File") {
                    return value.getAbsolutePath().toString();
                }

                return value.toString();
            } catch (error) {
                return `<error extracting path: ${error}>`;
            }
        }

        function serializeByteArray(value: any): {
            type: string;
            value_hex: string | null;
            length: number | null;
        } {
            if (!AndroidBase64 || !base64Encode) {
                return {
                    type: "byte[]",
                    value_hex: null,
                    length: null
                };
            }

            try {
                // android.util.Base64.NO_WRAP = 2
                const base64 = base64Encode
                    .call(AndroidBase64, value, 2)
                    .toString();
                const valueHex = base64ToHex(base64);

                return {
                    type: "byte[]",
                    value_hex: valueHex,
                    length: valueHex.length / 2
                };
            } catch (_) {
                return {
                    type: "byte[]",
                    value_hex: null,
                    length: null
                };
            }
        }

        function serializeValue(value: any): any {
            if (value === null || value === undefined) {
                return null;
            }

            if (
                typeof value === "string" ||
                typeof value === "number" ||
                typeof value === "boolean"
            ) {
                return value;
            }

            try {
                const runtimeClassName = value.getClass().getName().toString();

                if (runtimeClassName === "[B") {
                    return serializeByteArray(value);
                }

                const runtimeClass = Java.use(runtimeClassName);
                const typedValue = Java.cast(value, runtimeClass);

                switch (runtimeClassName) {
                    case "java.lang.String":
                    case "java.lang.CharSequence":
                    case "java.lang.Character":
                        return typedValue.toString();

                    case "java.lang.Boolean":
                        return typedValue.booleanValue();

                    case "java.lang.Byte":
                    case "java.lang.Short":
                    case "java.lang.Integer":
                        return typedValue.intValue();

                    case "java.lang.Long":
                        return typedValue.toString();

                    case "java.lang.Float":
                    case "java.lang.Double":
                        return typedValue.doubleValue();

                    default:
                        return {
                            type: runtimeClassName,
                            value: typedValue.toString()
                        };
                }
            } catch (error) {
                return `<error serializing value: ${error}>`;
            }
        }

        function serializeArray(values: any): any[] {
            if (!values) {
                return [];
            }

            const result: any[] = [];

            for (let index = 0; index < values.length; index++) {
                result.push(serializeValue(values[index]));
            }

            return result;
        }

        function serializeContentValues(values: any): Record<string, any> {
            const result: Record<string, any> = {};

            if (!values) {
                return result;
            }

            const iterator = values.keySet().iterator();

            while (iterator.hasNext()) {
                const key = iterator.next().toString();
                result[key] = serializeValue(values.get(key));
            }

            return result;
        }

        function serializeEncryptionKey(
            value: any,
            typeName: string
        ): { value: string | null; type: string | null } {
            if (value === null || value === undefined) {
                return {
                    value: null,
                    type: null
                };
            }

            if (typeName === "[B") {
                const serialized = serializeByteArray(value);

                return {
                    value: serialized.value_hex
                        ? `hex:${serialized.value_hex}`
                        : null,
                    type: "byte[]"
                };
            }

            return {
                value: serializeValue(value).toString(),
                type: typeName
            };
        }

        function decodeFlags(flags: number): string {
            const descriptions: string[] = [];

            // WCDB OPEN_READWRITE is zero, so it must be handled separately.
            if ((flags & 0x00000001) !== 0) {
                descriptions.push("OPEN_READONLY");
            } else {
                descriptions.push("OPEN_READWRITE");
            }

            if ((flags & 0x10000000) !== 0) {
                descriptions.push("CREATE_IF_NECESSARY");
            }

            if ((flags & 0x00000010) !== 0) {
                descriptions.push("NO_LOCALIZED_COLLATORS");
            }

            if ((flags & 0x00000100) !== 0) {
                descriptions.push("ENABLE_IO_TRACE");
            }

            if ((flags & 0x20000000) !== 0) {
                descriptions.push("ENABLE_WRITE_AHEAD_LOGGING");
            }

            return descriptions.join(" | ");
        }

        function findOpenFlagsArgument(
            methodName: string,
            overload: any,
            args: any[]
        ): { value: number | null; index: number | null } {
            const argumentTypes = overload.argumentTypes;

            // openDatabase(..., CursorFactory, int flags, ...)
            if (methodName === "openDatabase") {
                const factoryIndex = argumentTypes.findIndex(
                    (argument: any) =>
                        argument.className.includes("CursorFactory")
                );

                for (
                    let index = factoryIndex + 1;
                    index < argumentTypes.length;
                    index++
                ) {
                    if (argumentTypes[index].className === "int") {
                        return {
                            value: Number(args[index]),
                            index: index
                        };
                    }
                }
            }

            // openOrCreateDatabase(String, CursorFactory, int flags)
            if (
                methodName === "openOrCreateDatabase" &&
                argumentTypes.length === 3 &&
                argumentTypes[0].className === "java.lang.String" &&
                argumentTypes[1].className.includes("CursorFactory") &&
                argumentTypes[2].className === "int"
            ) {
                return {
                    value: Number(args[2]),
                    index: 2
                };
            }

            return {
                value: null,
                index: null
            };
        }

        function findConnectionPoolSizeArgument(
            overload: any,
            args: any[],
            flagsIndex: number | null
        ): number | null {
            const argumentTypes = overload.argumentTypes;

            for (let index = 0; index < argumentTypes.length; index++) {
                if (
                    argumentTypes[index].className === "int" &&
                    index !== flagsIndex
                ) {
                    return Number(args[index]);
                }
            }

            return null;
        }

        function hookOpenMethod(methodName: string): void {
            const method = (wcdbDatabase as any)[methodName];

            if (!method || !method.overloads) {
                return;
            }

            method.overloads.forEach((overload: any, index: number) => {
                const argumentTypes = overload.argumentTypes;
                const pathType = argumentTypes[0]?.className || "unknown";
                const signature = signatureOf(overload);

                overload.implementation = safeImplementation(
                    `database:WCDB.SQLiteDatabase.${methodName}[${index}]`,
                    overload,
                    function (original, ...args: any[]) {
                        if (!isNestedOpen()) {
                            const keyIndex = argumentTypes.findIndex(
                                (argument: any) => argument.className === "[B"
                            );
                            const key = keyIndex >= 0
                                ? serializeEncryptionKey(
                                    args[keyIndex],
                                    argumentTypes[keyIndex].className
                                )
                                : { value: null, type: null };

                            const flags = findOpenFlagsArgument(
                                methodName,
                                overload,
                                args
                            );
                            const connectionPoolSize =
                                findConnectionPoolSizeArgument(
                                    overload,
                                    args,
                                    flags.index
                                );

                            const hasFactory = argumentTypes.some(
                                (argument: any, argumentIndex: number) =>
                                    argument.className.includes("CursorFactory") &&
                                    args[argumentIndex] !== null
                            );
                            const hasErrorHandler = argumentTypes.some(
                                (argument: any, argumentIndex: number) =>
                                    argument.className.includes("DatabaseErrorHandler") &&
                                    args[argumentIndex] !== null
                            );
                            const hasCipherSpec = argumentTypes.some(
                                (argument: any, argumentIndex: number) =>
                                    argument.className.includes("SQLiteCipherSpec") &&
                                    args[argumentIndex] !== null
                            );

                            createDatabaseEvent("database.wcdb.open", {
                                method: `WCDB.SQLiteDatabase.${methodName}(${signature})`,
                                database_path: getPathArgument(args[0], pathType),
                                database_type: "WCDB",
                                password: key.value,
                                password_type: key.type,
                                flags: flags.value,
                                flags_description: flags.value !== null
                                    ? decodeFlags(flags.value)
                                    : null,
                                connection_pool_size: connectionPoolSize,
                                has_factory: hasFactory,
                                has_error_handler: hasErrorHandler,
                                has_cipher_spec: hasCipherSpec,
                                overload_signature: signature
                            });
                        }

                        return callWithOpenGuard(
                            () => original.apply(this, args)
                        );
                    }
                );
            });
        }

        // Hook every runtime-visible WCDB open overload.
        hookOpenMethod("openDatabase");
        hookOpenMethod("openOrCreateDatabase");

        function hookSqlMethod(
            methodName: string,
            eventType: string
        ): void {
            const method = (wcdbDatabase as any)[methodName];

            if (!method || !method.overloads) {
                return;
            }

            method.overloads.forEach((overload: any, index: number) => {
                const argumentTypes = overload.argumentTypes;
                const signature = signatureOf(overload);

                overload.implementation = safeImplementation(
                    `database:WCDB.SQLiteDatabase.${methodName}[${index}]`,
                    overload,
                    function (original, ...args: any[]) {
                        const sql = args[0] ? args[0].toString() : null;
                        const argsIndex = argumentTypes.findIndex(
                            (argument: any) =>
                                argument.className === "[Ljava.lang.Object;"
                        );
                        const cancellationIndex = argumentTypes.findIndex(
                            (argument: any) =>
                                argument.className.includes("CancellationSignal")
                        );

                        createDatabaseEvent(eventType, {
                            method: `WCDB.SQLiteDatabase.${methodName}(${signature})`,
                            database_path: getDatabasePath(this),
                            database_type: "WCDB",
                            sql: sql,
                            bind_args: argsIndex >= 0
                                ? serializeArray(args[argsIndex])
                                : [],
                            where_args: methodName === "rawQuery" && argsIndex >= 0
                                ? serializeArray(args[argsIndex])
                                : undefined,
                            cancellation_signal: cancellationIndex >= 0 &&
                                args[cancellationIndex] !== null,
                            overload_signature: signature
                        });

                        return original.apply(this, args);
                    }
                );
            });
        }

        hookSqlMethod("execSQL", "database.wcdb.exec");
        hookSqlMethod("rawQuery", "database.wcdb.query");

        function hookCrudMethod(
            methodName: string,
            eventType: string
        ): void {
            const method = (wcdbDatabase as any)[methodName];

            if (!method || !method.overloads) {
                return;
            }

            method.overloads.forEach((overload: any, index: number) => {
                const signature = signatureOf(overload);

                overload.implementation = safeImplementation(
                    `database:WCDB.SQLiteDatabase.${methodName}[${index}]`,
                    overload,
                    function (original, ...args: any[]) {
                        const table = args[0] ? args[0].toString() : null;
                        const databasePath = getDatabasePath(this);

                        if (methodName === "insert") {
                            createDatabaseEvent(eventType, {
                                method: `WCDB.SQLiteDatabase.insert(${signature})`,
                                database_path: databasePath,
                                database_type: "WCDB",
                                table: table,
                                null_column_hack: args[1]
                                    ? args[1].toString()
                                    : null,
                                content_values: serializeContentValues(args[2])
                            });
                        } else if (methodName === "update") {
                            createDatabaseEvent(eventType, {
                                method: `WCDB.SQLiteDatabase.update(${signature})`,
                                database_path: databasePath,
                                database_type: "WCDB",
                                table: table,
                                content_values: serializeContentValues(args[1]),
                                where_clause: args[2]
                                    ? args[2].toString()
                                    : null,
                                where_args: serializeArray(args[3])
                            });
                        } else if (methodName === "delete") {
                            createDatabaseEvent(eventType, {
                                method: `WCDB.SQLiteDatabase.delete(${signature})`,
                                database_path: databasePath,
                                database_type: "WCDB",
                                table: table,
                                where_clause: args[1]
                                    ? args[1].toString()
                                    : null,
                                where_args: serializeArray(args[2])
                            });
                        }

                        const result = original.apply(this, args);

                        if (methodName === "delete") {
                            createDatabaseEvent("database.wcdb.delete_result", {
                                method: `WCDB.SQLiteDatabase.delete(${signature})`,
                                database_path: databasePath,
                                database_type: "WCDB",
                                table: table,
                                rows_affected: result
                            });
                        }

                        return result;
                    }
                );
            });
        }

        hookCrudMethod("insert", "database.wcdb.insert");
        hookCrudMethod("update", "database.wcdb.update");
        hookCrudMethod("delete", "database.wcdb.delete");

        function hookTransactionMethod(
            methodName: string,
            transactionAction: string
        ): void {
            const method = (wcdbDatabase as any)[methodName];

            if (!method || !method.overloads) {
                return;
            }

            method.overloads.forEach((overload: any, index: number) => {
                const argumentTypes = overload.argumentTypes;
                const signature = signatureOf(overload);

                overload.implementation = safeImplementation(
                    `database:WCDB.SQLiteDatabase.${methodName}[${index}]`,
                    overload,
                    function (original, ...args: any[]) {
                        if (!isNestedTransaction()) {
                            const listenerIndex = argumentTypes.findIndex(
                                (argument: any) =>
                                    argument.className.includes("SQLiteTransactionListener")
                            );
                            const exclusiveIndex = argumentTypes.findIndex(
                                (argument: any) => argument.className === "boolean"
                            );

                            createDatabaseEvent("database.wcdb.transaction", {
                                method: `WCDB.SQLiteDatabase.${methodName}(${signature})`,
                                database_path: getDatabasePath(this),
                                database_type: "WCDB",
                                transaction_action: transactionAction,
                                has_listener: listenerIndex >= 0 &&
                                    args[listenerIndex] !== null,
                                exclusive: exclusiveIndex >= 0
                                    ? args[exclusiveIndex]
                                    : null,
                                overload_signature: signature
                            });
                        }

                        return callWithTransactionGuard(
                            () => original.apply(this, args)
                        );
                    }
                );
            });
        }

        hookTransactionMethod("beginTransaction", "begin");
        hookTransactionMethod("setTransactionSuccessful", "successful");
        hookTransactionMethod("endTransaction", "end");
    });
}


export function install_database_hooks(){
    devlog("\n")
    devlog("install sql hooks");

    try {
        hook_java_sql();
    } catch (error) {
        devlog(`[HOOK] Failed to install Java SQL hooks: ${error}`);
    }

    try {
        hook_SQLCipher();
    } catch (error) {
        devlog(`[HOOK] Failed to install SQLCipher hooks: ${error}`);
    }

    try {
        hook_wcdb(); // Add WCDB hooks
    } catch (error) {
        devlog(`[HOOK] Failed to install WCDB hooks: ${error}`);
    }

    try {
        hook_native_sqlite();
    } catch (error) {
        devlog(`[HOOK] Failed to install native SQLite hooks: ${error}`);
    }

    try {
        hook_room_library(); // e.g on the To Do List App this results into a crash/stopping of the target app
    } catch (error) {
        devlog(`[HOOK] Failed to install Room library hooks: ${error}`);
    }

    try {
        hook_sql_related_stuff();
    } catch (error) {
        devlog(`[HOOK] Failed to install SQL related hooks: ${error}`);
    }
}