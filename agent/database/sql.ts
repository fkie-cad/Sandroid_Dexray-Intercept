import { devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { Java} from "../utils/javalib.js"
import { safePerform, safeUse, safeDeferred, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { safeResolveExport, safeAttach } from "../utils/safe_native.js"

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

                    return original.call(this, sql);
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

// the room library is a famous SQL library on Android
function hook_room_library() {
    safePerform("database:hook_room_library", () => {
        //console.log("ROOM hooks being installed");

        // Hook the Room.databaseBuilder method
        const Room = safeUse("androidx.room.Room", "database:hook_room_library");
        if (!Room) {
            return;
        }

        const databaseBuilderRef = safeOverload(
            Room.databaseBuilder,
            "database:Room.databaseBuilder[Context,Class,String]",
            "android.content.Context", "java.lang.Class", "java.lang.String"
        );
        if (databaseBuilderRef) {
            databaseBuilderRef.implementation = safeImplementation(
                "database:Room.databaseBuilder[Context,Class,String]",
                databaseBuilderRef,
                function (original, context: any, klass: any, dbName: string) {
                    createDatabaseEvent("database.room.builder", {
                        method: "Room.databaseBuilder(Context, Class, String)",
                        database_name: dbName,
                        database_class: klass.toString(),
                        database_type: "Room"
                    });
                    return original.call(this, context, klass, dbName);
                }
            );
        }

        // // Hook SQLiteDatabase.openOrCreateDatabase (only if SQLCipher is present)
        // const SQLiteDatabase = safeUse(
        //     "net.sqlcipher.database.SQLiteDatabase",
        //     "database:hook_room_library"
        // );
        // if (SQLiteDatabase) {
        //     const openOrCreate_File_String = safeOverload(
        //         SQLiteDatabase.openOrCreateDatabase,
        //         "database:SQLiteDatabase.openOrCreateDatabase[File,String]_Room",
        //         "java.io.File",
        //         "java.lang.String"
        //     );
        //     if (openOrCreate_File_String) {
        //         openOrCreate_File_String.implementation = safeImplementation(
        //             "database:SQLiteDatabase.openOrCreateDatabase[File,String]_Room",
        //             openOrCreate_File_String,
        //             function (original, file: any, password: string) {
        //                 const methodVal = "SQLiteDatabase.openOrCreateDatabase(File, String), ";
        //                 const logVal = `Opening or creating database with file: ${file.getAbsolutePath()} and password: ${password}`;
        //                 am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
        //                 //console.log(logVal);
        //                 return original.call(this, file, password);
        //             }
        //         );
        //     }

        //     const openOrCreate_String_String = safeOverload(
        //         SQLiteDatabase.openOrCreateDatabase,
        //         "database:SQLiteDatabase.openOrCreateDatabase[String,String]_Room",
        //         "java.lang.String",
        //         "java.lang.String"
        //     );
        //     if (openOrCreate_String_String) {
        //         openOrCreate_String_String.implementation = safeImplementation(
        //             "database:SQLiteDatabase.openOrCreateDatabase[String,String]_Room",
        //             openOrCreate_String_String,
        //             function (original, path: string, password: string) {
        //                 const methodVal = "SQLiteDatabase.openOrCreateDatabase(String, String), ";
        //                 const logVal = `Opening or creating database with path: ${path} and password: ${password}`;
        //                 am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
        //                 //console.log(logVal);
        //                 return original.call(this, path, password);
        //             }
        //         );
        //     }

        //     // Hook PRAGMA key setting for SQLCipher
        //     const execSQL_String_SQLCipherRoom = safeOverload(
        //         SQLiteDatabase.execSQL,
        //         "database:SQLiteDatabase.execSQL[String]_Room_SQLCipherPragma",
        //         "java.lang.String"
        //     );
        //     if (execSQL_String_SQLCipherRoom) {
        //         execSQL_String_SQLCipherRoom.implementation = safeImplementation(
        //             "database:SQLiteDatabase.execSQL[String]_Room_SQLCipherPragma",
        //             execSQL_String_SQLCipherRoom,
        //             function (original, sql: string) {
        //                 if (sql.toLowerCase().includes("pragma key")) {
        //                     createDatabaseEvent("database.sqlcipher.pragma", {
        //                         method: "SQLiteDatabase.execSQL(String)",
        //                         sql: sql,
        //                         pragma_type: "key",
        //                         database_type: "SQLCipher"
        //                     });
        //                 }
        //                 return original.call(this, sql);
        //             }
        //         );
        //     }
        // } // End if (SQLiteDatabase)

        // Hook SupportSQLiteOpenHelper.Callback onCreate / onOpen
        const SupportSQLiteOpenHelper_Callback = safeUse(
            "androidx.sqlite.db.SupportSQLiteOpenHelper$Callback",
            "database:hook_room_library"
        );
        if (SupportSQLiteOpenHelper_Callback) {
            const onCreateRef = SupportSQLiteOpenHelper_Callback.onCreate;
            if (onCreateRef) {
                onCreateRef.implementation = safeImplementation(
                    "database:SupportSQLiteOpenHelper.Callback.onCreate",
                    onCreateRef,
                    function (original, db: any) {
                        createDatabaseEvent("database.room.callback", {
                            method: "SupportSQLiteOpenHelper.Callback.onCreate(SupportSQLiteDatabase)",
                            database_object: db.toString(),
                            callback_type: "onCreate",
                            database_type: "Room"
                        });
                        return original.call(this, db);
                    }
                );
            }


            const onOpenRef = SupportSQLiteOpenHelper_Callback.onOpen;
            if (onOpenRef) {
                onOpenRef.implementation = safeImplementation(
                    "database:SupportSQLiteOpenHelper.Callback.onOpen",
                    onOpenRef,
                    function (original, db: any) {
                        createDatabaseEvent("database.room.callback", {
                            method: "SupportSQLiteOpenHelper.Callback.onOpen(SupportSQLiteDatabase)",
                            database_object: db.toString(),
                            callback_type: "onOpen",
                            database_type: "Room"
                        });
                        return original.call(this, db);
                    }
                );
            }
        } // End if (SupportSQLiteOpenHelper_Callback)


            // Hook DAO methods (insert, update, delete)
        const Dao = safeUse("androidx.room.RoomDatabase", "database:hook_room_library");
        if (Dao) {
            const insertRef = safeOverload(
                Dao.insert,
                "database:RoomDatabase.insert[Object]",
                "java.lang.Object"
            );
            if (insertRef) {
                insertRef.implementation = safeImplementation(
                    "database:RoomDatabase.insert[Object]",
                    insertRef,
                    function (original, entity: any) {
                        createDatabaseEvent("database.room.dao", {
                            method: "RoomDatabase.insert(Object)",
                            entity: entity.toString(),
                            dao_operation: "insert",
                            database_type: "Room"
                        });
                        return original.call(this, entity);
                    }
                );
            }

            const updateRef = safeOverload(
                Dao.update,
                "database:RoomDatabase.update[Object]",
                "java.lang.Object"
            );
            if (updateRef) {
                updateRef.implementation = safeImplementation(
                    "database:RoomDatabase.update[Object]",
                    updateRef,
                    function (original, entity: any) {
                        createDatabaseEvent("database.room.dao", {
                            method: "RoomDatabase.update(Object)",
                            entity: entity.toString(),
                            dao_operation: "update",
                            database_type: "Room"
                        });
                        return original.call(this, entity);
                    }
                );
            }

            const deleteRef = safeOverload(
                Dao.delete,
                "database:RoomDatabase.delete[Object]",
                "java.lang.Object"
            );
            if (deleteRef) {
                deleteRef.implementation = safeImplementation(
                    "database:RoomDatabase.delete[Object]",
                    deleteRef,
                    function (original, entity: any) {
                        createDatabaseEvent("database.room.dao", {
                            method: "RoomDatabase.delete(Object)",
                            entity: entity.toString(),
                            dao_operation: "delete",
                            database_type: "Room"
                        });
                        return original.call(this, entity);
                    }
                );
            }
        } // End if (Dao)

        // Hook query execution (using same Dao reference as RoomDatabase)
        if (Dao) {
            const queryRef = safeOverload(
                Dao.query,
                "database:RoomDatabase.query[SupportSQLiteQuery]",
                "androidx.sqlite.db.SupportSQLiteQuery"
            );
            if (queryRef) {
                queryRef.implementation = safeImplementation(
                    "database:RoomDatabase.query[SupportSQLiteQuery]",
                    queryRef,
                    function (original, query: any) {
                        const methodVal = "RoomDatabase.query, ";
                        const logVal = `Query executed: ${query.toString()}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Database, ${methodVal}${logVal}`);
                        return original.call(this, query);
                    }
                );
            }
        } // End if (Dao)

        // Hook SupportSQLiteDatabase execSQL
        const SupportSQLiteDatabase = safeUse(
            "androidx.sqlite.db.SupportSQLiteDatabase",
            "database:hook_room_library"
        );
        if (SupportSQLiteDatabase) {
            const execSQL_String_RoomSupport = safeOverload(
                SupportSQLiteDatabase.execSQL,
                "database:SupportSQLiteDatabase.execSQL[String]",
                "java.lang.String"
            );
            if (execSQL_String_RoomSupport) {
                execSQL_String_RoomSupport.implementation = safeImplementation(
                    "database:SupportSQLiteDatabase.execSQL[String]",
                    execSQL_String_RoomSupport,
                    function (original, sql: string) {
                        const methodVal = "SupportSQLiteDatabase.execSQL, ";
                        const logVal = `Executing SQL: ${sql}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Database, ${methodVal}${logVal}`);
                        return original.call(this, sql);
                    }
                );
            }
        } // End if (SupportSQLiteDatabase)

        // Hook LiveData observe
        const LiveData = safeUse("androidx.lifecycle.LiveData", "database:hook_room_library");
        if (LiveData) {
            const observeRef = safeOverload(
                LiveData.observe,
                "database:LiveData.observe[LifecycleOwner,Observer]",
                "androidx.lifecycle.LifecycleOwner",
                "androidx.lifecycle.Observer"
            );
            if (observeRef) {
                observeRef.implementation = safeImplementation(
                    "database:LiveData.observe[LifecycleOwner,Observer]",
                    observeRef,
                    function (original, owner: any, observer: any) {
                        const methodVal = "LiveData.observe, ";
                        const logVal = `LiveData observed with LifecycleOwner: ${owner.toString()}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: Room.LiveData, ${methodVal}${logVal}`);
                        return original.call(this, owner, observer);
                    }
                );
            }
        } // End if (LiveData)

        // Hook Flow collect
        const FlowCollector = safeUse(
            "kotlinx.coroutines.flow.FlowCollector",
            "database:hook_room_library"
        );
        if (FlowCollector) {
            const emitRef = safeOverload(
                FlowCollector.emit,
                "database:FlowCollector.emit[Object]",
                "java.lang.Object"
            );
            if (emitRef) {
                emitRef.implementation = safeImplementation(
                    "database:FlowCollector.emit[Object]",
                    emitRef,
                    function (original, value: any) {
                        const methodVal = "FlowCollector.emit, ";
                        const logVal = `Flow emitted value: ${value}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Flow, ${methodVal}${logVal}`);
                        return original.call(this, value);
                    }
                );
            }
        } // End if (FlowCollector)

    });
}

function hook_native_sqlite() {
    devlog("Installing native SQLite hooks");
    
    // Only proceed with native hooking if we can find the SQLite library
    const sqlite_modules = Process.enumerateModules()
        .filter(m => m.name.toLowerCase().includes("sqlite") || m.name.toLowerCase().includes("libsqlite"));
    
    if (sqlite_modules.length === 0) {
        devlog("No SQLite native libraries found to hook");
        return;
    }
    
    devlog(`Found ${sqlite_modules.length} SQLite related modules: ${sqlite_modules.map(m => m.name).join(", ")}`);
    
    // Hook core SQLite functions in each module
    sqlite_modules.forEach(module => {
        devlog(`Hooking SQLite functions in ${module.name}`);
        
        // Helper function to safely hook a native function. safeResolveExport
        // handles the null/throw cases and logs them via hookError; we keep the
        // module-scoped success/miss devlog for readability.
        function hookFunction(name, successCallback) {
            const address = safeResolveExport(module.name, name, `database:${name}`);
            if (address) {
                successCallback(address);
                devlog(`✅ Successfully hooked ${name} in ${module.name}`);
            } else {
                devlog(`⚠️ Could not find export for ${name} in ${module.name}`);
            }
        }
        
        // Hook sqlite3_open and variants
        ["sqlite3_open", "sqlite3_open_v2", "sqlite3_open16"].forEach(funcName => {
            hookFunction(funcName, address => {
                safeAttach(address, `database:${funcName}`, {
                    onEnter: function(args) {
                        this.dbPath = args[0].readUtf8String();
                        this.dbHandle = args[1]; // Store for later use in onLeave
                    },
                    onLeave: function(retval) {
                        const resultCode = retval.toInt32();
                        const status = resultCode === 0 ? "success" : `error code ${resultCode}`;
                        
                        createDatabaseEvent("database.native.open", {
                            method: funcName,
                            database_path: this.dbPath,
                            result_code: resultCode,
                            status: status,
                            database_type: "Native SQLite"
                        });
                    }
                });
            });
        });
        
        // Hook sqlite3_exec (direct SQL execution)
        hookFunction("sqlite3_exec", address => {
            safeAttach(address, "database:sqlite3_exec", {
                onEnter: function(args) {
                    const dbHandle = args[0];
                    const sql = args[1].readUtf8String();
                    
                    createDatabaseEvent("database.native.exec", {
                        method: "sqlite3_exec",
                        sql: sql,
                        database_type: "Native SQLite"
                    });
                }
            });
        });
        
        // Hook sqlite3_prepare and variants (SQL statement preparation)
        ["sqlite3_prepare", "sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_prepare16", "sqlite3_prepare16_v2", "sqlite3_prepare16_v3"].forEach(funcName => {
            hookFunction(funcName, address => {
                safeAttach(address, `database:${funcName}`, {
                    onEnter: function(args) {
                        const sql = args[1].readUtf8String();
                        this.sql = sql;
                    },
                    onLeave: function(retval) {
                        const resultCode = retval.toInt32();
                        const status = resultCode === 0 ? "success" : `error code ${resultCode}`;
                        
                        am_send(PROFILE_HOOKING_TYPE, `event_type: NativeSQLite, method: ${funcName},
                        sql: ${this.sql},
                        status: ${status}`);
                    }
                });
            });
        });
        
        // Hook sqlite3_step (statement execution)
        hookFunction("sqlite3_step", address => {
            safeAttach(address, "database:sqlite3_step", {
                onEnter: function(args) {
                    this.stmtHandle = args[0];
                },
                onLeave: function(retval) {
                    // Result codes: SQLITE_DONE(101), SQLITE_ROW(100), etc.
                    const resultCode = retval.toInt32();
                    let status = "unknown";
                    
                    if (resultCode === 100) status = "row available";
                    else if (resultCode === 101) status = "completed";
                    else status = `error code ${resultCode}`;
                    
                    am_send(PROFILE_HOOKING_TYPE, `event_type: NativeSQLite, method: sqlite3_step,
                    status: ${status}`);
                }
            });
        });
        
        // Hook sqlite3_close and sqlite3_close_v2
        ["sqlite3_close", "sqlite3_close_v2"].forEach(funcName => {
            hookFunction(funcName, address => {
                safeAttach(address, `database:${funcName}`, {
                    onEnter: function(args) {
                        this.dbHandle = args[0];
                    },
                    onLeave: function(retval) {
                        const resultCode = retval.toInt32();
                        const status = resultCode === 0 ? "success" : `error code ${resultCode}`;
                        
                        am_send(PROFILE_HOOKING_TYPE, `event_type: NativeSQLite, method: ${funcName},
                        status: ${status}`);
                    }
                });
            });
        });
        
        // Hook sqlite3_bind_* functions (for parameter binding)
        ["sqlite3_bind_text", "sqlite3_bind_blob", "sqlite3_bind_int", "sqlite3_bind_int64", "sqlite3_bind_double", "sqlite3_bind_null"].forEach(funcName => {
            hookFunction(funcName, address => {
                safeAttach(address, `database:${funcName}`, {
                    onEnter: function(args) {
                        const stmtHandle = args[0];
                        const paramIndex = args[1].toInt32();
                        
                        let paramValue = "unknown";
                        try {
                            if (funcName === "sqlite3_bind_text" || funcName === "sqlite3_bind_blob") {
                                paramValue = args[2].readUtf8String();
                            } else if (funcName === "sqlite3_bind_int") {
                                paramValue = args[2].toInt32().toString();
                            } else if (funcName === "sqlite3_bind_int64") {
                                paramValue = args[2].toString();
                            } else if (funcName === "sqlite3_bind_double") {
                                paramValue = args[2].readDouble().toString();
                            } else if (funcName === "sqlite3_bind_null") {
                                paramValue = "NULL";
                            }
                        } catch (e) {
                            paramValue = "Error reading value";
                        }
                        
                        am_send(PROFILE_HOOKING_TYPE, `event_type: NativeSQLite, method: ${funcName},
                        index: ${paramIndex},
                        value: ${paramValue}`);
                    }
                });
            });
        });
    });
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
        devlog("WCDB hooks being installed");

        // Helper function to interpret database flags - same as in SQLite
        function interpretDatabaseFlags(flags) {
            const flagsMap = {
                0x00000000: "OPEN_READONLY",
                0x00000001: "OPEN_READWRITE",
                0x00000002: "CREATE_IF_NECESSARY",
                0x00000004: "NO_LOCALIZED_COLLATORS",
                0x00000008: "ENABLE_WRITE_AHEAD_LOGGING",
                0x00000010: "OPEN_URI",
                0x00000020: "ENABLE_FOREIGN_KEY_CONSTRAINTS",
                0x20000000: "OPEN_NOMUTEX",
                0x10000000: "OPEN_FULLMUTEX"
            };

            const flagDescriptions: string[] = [];
            for (const flag in flagsMap) {
                const numericFlag = parseInt(flag);
                if ((flags & numericFlag) === numericFlag) {
                    flagDescriptions.push(flagsMap[flag]);
                }
            }

            return flagDescriptions.length > 0 ? flagDescriptions.join(" | ") : "UNKNOWN_FLAG";
        }

        // openDatabase(String, CursorFactory, int)
        const openDatabase_String_CursorFactory_int_WCDB = safeOverload(
            wcdbDatabase.openDatabase,
            "database:WCDB.SQLiteDatabase.openDatabase[String,CursorFactory,int]",
            'java.lang.String',
            'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory',
            'int'
        );
        if (openDatabase_String_CursorFactory_int_WCDB) {
            openDatabase_String_CursorFactory_int_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.openDatabase[String,CursorFactory,int]",
                openDatabase_String_CursorFactory_int_WCDB,
                function (original, path: string, factory: any, flags: number) {
                    const type = "\x1b[1;36mevent_type: WCDBOpenDatabase\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.openDatabase";

                    if (shouldLogDatabasePath(path)) {
                        const flagsDescription = interpretDatabaseFlags(flags);
                        const logVal =
                            "\nOpening WCDB database: " + '\x1b[36m' + path + '\x1b[0m' +
                            "\nFlags: " + '\x1b[33m' + flags + " (" + flagsDescription + ")" + '\x1b[0m' +
                            "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, path, factory, flags);
                }
            );
        }

        // openOrCreateDatabase(String, CursorFactory)
        const openOrCreateDatabase_String_CursorFactory_WCDB = safeOverload(
            wcdbDatabase.openOrCreateDatabase,
            "database:WCDB.SQLiteDatabase.openOrCreateDatabase[String,CursorFactory]",
            'java.lang.String',
            'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory'
        );
        if (openOrCreateDatabase_String_CursorFactory_WCDB) {
            openOrCreateDatabase_String_CursorFactory_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.openOrCreateDatabase[String,CursorFactory]",
                openOrCreateDatabase_String_CursorFactory_WCDB,
                function (original, path: string, factory: any) {
                    const type = "\x1b[1;36mevent_type: WCDBOpenDatabase\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.openOrCreateDatabase";

                    if (shouldLogDatabasePath(path)) {
                        const logVal =
                            "\nOpening or creating WCDB database: " + '\x1b[36m' + path + '\x1b[0m' +
                            "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, path, factory);
                }
            );
        }

        // execSQL(String)
        const execSQL_String_WCDB = safeOverload(
            wcdbDatabase.execSQL,
            "database:WCDB.SQLiteDatabase.execSQL[String]",
            'java.lang.String'
        );
        if (execSQL_String_WCDB) {
            execSQL_String_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.execSQL[String]",
                execSQL_String_WCDB,
                function (original, sql: string) {
                    const type = "\x1b[1;35mevent_type: WCDBExecSQL\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.execSQL";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nExecuting SQL: " + '\x1b[36m' + sql + '\x1b[0m' + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, sql);
                }
            );
        }

        // execSQL(String, Object[])
        const execSQL_String_ObjectArray_WCDB = safeOverload(
            wcdbDatabase.execSQL,
            "database:WCDB.SQLiteDatabase.execSQL[String,Object[]]",
            'java.lang.String',
            '[Ljava.lang.Object;'
        );
        if (execSQL_String_ObjectArray_WCDB) {
            execSQL_String_ObjectArray_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.execSQL[String,Object[]]",
                execSQL_String_ObjectArray_WCDB,
                function (original, sql: string, bindArgs: any[]) {
                    const type = "\x1b[1;35mevent_type: WCDBExecSQL\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.execSQL";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let argsStr = "";
                        if (bindArgs && bindArgs.length > 0) {
                            for (let i = 0; i < bindArgs.length; i++) {
                                argsStr += "\n    - [" + i + "] " + bindArgs[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nExecuting SQL: " + '\x1b[36m' + sql + '\x1b[0m' +
                            "\nBind arguments:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, sql, bindArgs);
                }
            );
        }

        // rawQuery(String, String[])
        const rawQuery_String_StringArray_WCDB = safeOverload(
            wcdbDatabase.rawQuery,
            "database:WCDB.SQLiteDatabase.rawQuery[String,String[]]",
            'java.lang.String',
            '[Ljava.lang.String;'
        );
        if (rawQuery_String_StringArray_WCDB) {
            rawQuery_String_StringArray_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.rawQuery[String,String[]]",
                rawQuery_String_StringArray_WCDB,
                function (original, sql: string, selectionArgs: string[]) {
                    const type = "\x1b[1;34mevent_type: WCDBRawQuery\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.rawQuery";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let argsStr = "";
                        if (selectionArgs && selectionArgs.length > 0) {
                            for (let i = 0; i < selectionArgs.length; i++) {
                                argsStr += "\n    - [" + i + "] " + selectionArgs[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nSQL Query: " + '\x1b[36m' + sql + '\x1b[0m' +
                            "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, sql, selectionArgs);
                }
            );
        }

        // insert(String, String, ContentValues)
        const insert_String_String_ContentValues_WCDB = safeOverload(
            wcdbDatabase.insert,
            "database:WCDB.SQLiteDatabase.insert[String,String,ContentValues]",
            'java.lang.String',
            'java.lang.String',
            'android.content.ContentValues'
        );
        if (insert_String_String_ContentValues_WCDB) {
            insert_String_String_ContentValues_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.insert[String,String,ContentValues]",
                insert_String_String_ContentValues_WCDB,
                function (original, table: string, nullColumnHack: string, values: any) {
                    const type = "\x1b[1;33mevent_type: WCDBInsert\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.insert";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let valuesStr = "";
                        if (values) {
                            const keyset = values.keySet();
                            const iter = keyset.iterator();
                            while (iter.hasNext()) {
                                const key = iter.next();
                                const value = values.get(key);
                                valuesStr += "\n    - " + key + " = " + value;
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nInsert into table: " + '\x1b[36m' + table + '\x1b[0m' +
                            "\nNull column hack: " + '\x1b[35m' + (nullColumnHack ? nullColumnHack : "null") + '\x1b[0m' +
                            "\nValues to insert:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, table, nullColumnHack, values);
                }
            );
        }

        // update(String, ContentValues, String, String[])
        const update_String_ContentValues_String_StringArray_WCDB = safeOverload(
            wcdbDatabase.update,
            "database:WCDB.SQLiteDatabase.update[String,ContentValues,String,String[]]",
            'java.lang.String',
            'android.content.ContentValues',
            'java.lang.String',
            '[Ljava.lang.String;'
        );
        if (update_String_ContentValues_String_StringArray_WCDB) {
            update_String_ContentValues_String_StringArray_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.update[String,ContentValues,String,String[]]",
                update_String_ContentValues_String_StringArray_WCDB,
                function (original, table: string, values: any, whereClause: string, whereArgs: string[]) {
                    const type = "\x1b[1;32mevent_type: WCDBUpdate\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.update";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let valuesStr = "";
                        if (values) {
                            const keyset = values.keySet();
                            const iter = keyset.iterator();
                            while (iter.hasNext()) {
                                const key = iter.next();
                                const value = values.get(key);
                                valuesStr += "\n    - " + key + " = " + value;
                            }
                        }

                        let whereArgsStr = "";
                        if (whereArgs && whereArgs.length > 0) {
                            for (let i = 0; i < whereArgs.length; i++) {
                                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nUpdate table: " + '\x1b[36m' + table + '\x1b[0m' +
                            "\nWhere clause: " + '\x1b[35m' + whereClause + '\x1b[0m' +
                            "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") +
                            "\nValues to update:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, table, values, whereClause, whereArgs);
                }
            );
        }

        // delete(String, String, String[])
        const delete_String_String_StringArray_WCDB = safeOverload(
            wcdbDatabase.delete,
            "database:WCDB.SQLiteDatabase.delete[String,String,String[]]",
            'java.lang.String',
            'java.lang.String',
            '[Ljava.lang.String;'
        );
        if (delete_String_String_StringArray_WCDB) {
            delete_String_String_StringArray_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.delete[String,String,String[]]",
                delete_String_String_StringArray_WCDB,
                function (original, table: string, whereClause: string, whereArgs: string[]) {
                    const type = "\x1b[1;31mevent_type: WCDBDelete\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.delete";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let whereArgsStr = "";
                        if (whereArgs && whereArgs.length > 0) {
                            for (let i = 0; i < whereArgs.length; i++) {
                                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nDelete from table: " + '\x1b[36m' + table + '\x1b[0m' +
                            "\nWhere clause: " + '\x1b[35m' + (whereClause ? whereClause : "null (delete all rows)") + '\x1b[0m' +
                            "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    const deleteRes = original.call(this, table, whereClause, whereArgs);

                    if (shouldLogDatabasePath(dbPath)) {
                        const rowCountMsg = "Rows affected: " + '\x1b[32m' + deleteRes + '\x1b[0m';
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + " " + rowCountMsg);
                    }

                    return deleteRes;
                }
            );
        }

        // Transaction hooks
        const beginTransactionRef_WCDB = wcdbDatabase.beginTransaction;
        if (beginTransactionRef_WCDB) {
            beginTransactionRef_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.beginTransaction",
                beginTransactionRef_WCDB,
                function (original) {
                    const type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.beginTransaction";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nBeginning transaction" + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this);
                }
            );
        }

        const endTransactionRef_WCDB = wcdbDatabase.endTransaction;
        if (endTransactionRef_WCDB) {
            endTransactionRef_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.endTransaction",
                endTransactionRef_WCDB,
                function (original) {
                    const type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.endTransaction";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nEnding transaction" + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this);
                }
            );
        }

        const setTransactionSuccessfulRef_WCDB = wcdbDatabase.setTransactionSuccessful;
        if (setTransactionSuccessfulRef_WCDB) {
            setTransactionSuccessfulRef_WCDB.implementation = safeImplementation(
                "database:WCDB.SQLiteDatabase.setTransactionSuccessful",
                setTransactionSuccessfulRef_WCDB,
                function (original) {
                    const type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    const methodVal = "WCDB.SQLiteDatabase.setTransactionSuccessful";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nMarking transaction as successful" + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this);
                }
            );
        }
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