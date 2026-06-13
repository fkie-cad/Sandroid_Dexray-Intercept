import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
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

        // execSQL(String sql)
        const execSQL_String = safeOverload(
            sqliteDatabase.execSQL,
            "database:SQLiteDatabase.execSQL[String]",
            'java.lang.String'
        );
        if (execSQL_String) {
            execSQL_String.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String]",
                execSQL_String,
                function (original, sql: string) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        createDatabaseEvent("database.sqlite.exec", {
                            method: "SQLiteDatabase.execSQL(String)",
                            database_path: dbPath,
                            sql: sql
                        });
                    }

                    return original.call(this, sql);
                }
            );
        }

        // execSQL(String sql, Object[] bindArgs)
        const execSQL_String_ObjectArray = safeOverload(
            sqliteDatabase.execSQL,
            "database:SQLiteDatabase.execSQL[String,Object[]]",
            'java.lang.String', '[Ljava.lang.Object;'
        );
        if (execSQL_String_ObjectArray) {
            execSQL_String_ObjectArray.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String,Object[]]",
                execSQL_String_ObjectArray,
                function (original, sql: string, bindArgsArray: any[]) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const bindArgs: any[] = [];
                        if (bindArgsArray && bindArgsArray.length > 0) {
                            for (let i = 0; i < bindArgsArray.length; i++) {
                                bindArgs.push(bindArgsArray[i]);
                            }
                        }

                        createDatabaseEvent("database.sqlite.exec", {
                            method: "SQLiteDatabase.execSQL(String, Object[])",
                            database_path: dbPath,
                            sql: sql,
                            bind_args: bindArgs
                        });
                    }

                    return original.call(this, sql, bindArgsArray);
                }
            );
        }

        // query(boolean distinct, String table, String[] columns, String selection,
        //       String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
        const query_distinct_full = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String]",
            'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String',
            'java.lang.String', 'java.lang.String'
        );
        if (query_distinct_full) {
            query_distinct_full.implementation = safeImplementation(
                "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String]",
                query_distinct_full,
                function (original, distinct: boolean, table: string, columns: any, selection: string, selectionArgs: any,
                            groupBy: string, having: string, orderBy: string, limit: string) {
                    const methodVal = "SQLiteDatabase.query called.";
                    const logVal = "Table: " + table + ", selection value: " + selection +
                                    ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
                    am_send(PROFILE_HOOKING_TYPE, methodVal + " " + logVal + "\n");
                    return original.call(this, distinct, table, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
                }
            );
        }

        // query(String table, String[] columns, String selection, String[] selectionArgs,
        //       String groupBy, String having, String orderBy, String limit)
        const query_full = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String,String]",
            'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String'
        );
        if (query_full) {
            query_full.implementation = safeImplementation(
                "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String,String]",
                query_full,
                function (original, table: string, columnsArray: any, selection: string, selectionArgsArray: any,
                            groupBy: string, having: string, orderBy: string, limit: string) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const columns = columnsArray ? Array.prototype.slice.call(columnsArray) : [];
                        const selectionArgs = selectionArgsArray ? Array.prototype.slice.call(selectionArgsArray) : [];

                        createDatabaseEvent("database.sqlite.query", {
                            method: "SQLiteDatabase.query(String, String[], String, String[], String, String, String, String)",
                            database_path: dbPath,
                            table: table,
                            columns: columns,
                            where_clause: selection,
                            where_args: selectionArgs,
                            group_by: groupBy,
                            having: having,
                            order_by: orderBy,
                            limit: limit
                        });
                    }

                    return original.call(this, table, columnsArray, selection, selectionArgsArray, groupBy, having, orderBy, limit);
                }
            );
        }

        // query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs,
        //       String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
        const query_distinct_full_cancel = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
            'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String',
            'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal'
        );
        if (query_distinct_full_cancel) {
            query_distinct_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.query[boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
                query_distinct_full_cancel,
                function (original, distinct: boolean, table: string, columns: any, selection: string,
                            selectionArgs: any, groupBy: string, having: string,
                            orderBy: string, limit: string, cancellationSignal: any) {
                    const methodVal = "SQLiteDatabase.query called.";
                    const logVal = "Table: " + table + ", selection value: " + selection +
                                    ", selectionArgs: " + selectionArgs;
                    am_send(PROFILE_HOOKING_TYPE, methodVal + " " + logVal + "\n");
                    return original.call(this, distinct, table, columns, selection, selectionArgs,
                                            groupBy, having, orderBy, limit, cancellationSignal);
                }
            );
        }

        // query(String table, String[] columns, String selection, String[] selectionArgs,
        //       String groupBy, String having, String orderBy)
        const query_short = safeOverload(
            sqliteDatabase.query,
            "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String]",
            'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
            'java.lang.String', 'java.lang.String', 'java.lang.String'
        );
        if (query_short) {
            query_short.implementation = safeImplementation(
                "database:SQLiteDatabase.query[String,String[],String,String[],String,String,String]",
                query_short,
                function (original, table: string, columns: any, selection: string,
                            selectionArgs: any, groupBy: string, having: string, orderBy: string) {
                    const methodVal = "SQLiteDatabase.query called.";
                    const logVal = "Table: " + table + ", selection value: " + selection +
                                    ", selectionArgs: " + selectionArgs;
                    am_send(PROFILE_HOOKING_TYPE, methodVal + " " + logVal + "\n");
                    return original.call(this, table, columns, selection, selectionArgs, groupBy, having, orderBy);
                }
            );
        }

        // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns,
        //                  String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
        const queryWithFactory_full = safeOverload(
            sqliteDatabase.queryWithFactory,
            "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String]",
            'android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String'
        );
        if (queryWithFactory_full) {
            queryWithFactory_full.implementation = safeImplementation(
                "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String]",
                queryWithFactory_full,
                function (original, factory: any, distinct: boolean, table: string, columns: any,
                            selection: string, selectionArgs: any, groupBy: string, having: string,
                            orderBy: string, limit: string) {
                    const methodVal = "SQLiteDatabase.queryWithFactory called.";
                    const logVal = "Table: " + table + ", selection value: " + selection +
                                    ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
                    am_send(PROFILE_HOOKING_TYPE, methodVal + " " + logVal + "\n");
                    return original.call(this, factory, distinct, table, columns,
                                            selection, selectionArgs, groupBy, having, orderBy, limit);
                }
            );
        }

        // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns,
        //                  String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
        const queryWithFactory_full_cancel = safeOverload(
            sqliteDatabase.queryWithFactory,
            "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
            'android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.os.CancellationSignal'
        );
        if (queryWithFactory_full_cancel) {
            queryWithFactory_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.queryWithFactory[CursorFactory,boolean,String,String[],String,String[],String,String,String,String,CancellationSignal]",
                queryWithFactory_full_cancel,
                function (original, factory: any, distinct: boolean, table: string, columns: any,
                            selection: string, selectionArgs: any, groupBy: string, having: string,
                            orderBy: string, limit: string, cancellationSignal: any) {
                    const methodVal = "SQLiteDatabase.queryWithFactory called.";
                    const logVal = "Table: " + table + ", selection value: " + selection +
                                    ", selectionArgs: " + selectionArgs + " distinct: " + distinct;
                    am_send(PROFILE_HOOKING_TYPE, methodVal + " " + logVal + "\n");
                    return original.call(this, factory, distinct, table, columns,
                                            selection, selectionArgs, groupBy, having, orderBy, limit, cancellationSignal);
                }
            );
        }

        // rawQuery(String sql, String[] selectionArgs)
        const rawQuery_String_StringArray = safeOverload(
            sqliteDatabase.rawQuery,
            "database:SQLiteDatabase.rawQuery[String,String[]]",
            'java.lang.String', '[Ljava.lang.String;'
        );
        if (rawQuery_String_StringArray) {
            rawQuery_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQuery[String,String[]]",
                rawQuery_String_StringArray,
                function (original, sql: string, selectionArgsArray: string[]) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const selectionArgs: string[] = [];
                        if (selectionArgsArray && selectionArgsArray.length > 0) {
                            for (let i = 0; i < selectionArgsArray.length; i++) {
                                selectionArgs.push(selectionArgsArray[i]);
                            }
                        }

                        createDatabaseEvent("database.sqlite.query", {
                            method: "SQLiteDatabase.rawQuery(String, String[])",
                            database_path: dbPath,
                            sql: sql,
                            where_args: selectionArgs
                        });
                    }

                    return original.call(this, sql, selectionArgsArray);
                }
            );
        }

        // rawQuery(String sql, String[] selectionArgs, CancellationSignal cancellationSignal)
        const rawQuery_String_StringArray_Cancellation = safeOverload(
            sqliteDatabase.rawQuery,
            "database:SQLiteDatabase.rawQuery[String,String[],CancellationSignal]",
            'java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal'
        );
        if (rawQuery_String_StringArray_Cancellation) {
            rawQuery_String_StringArray_Cancellation.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQuery[String,String[],CancellationSignal]",
                rawQuery_String_StringArray_Cancellation,
                function (original, sql: string, selectionArgsArray: string[], cancellationSignal: any) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const selectionArgs: string[] = [];
                        if (selectionArgsArray && selectionArgsArray.length > 0) {
                            for (let i = 0; i < selectionArgsArray.length; i++) {
                                selectionArgs.push(selectionArgsArray[i]);
                            }
                        }

                        createDatabaseEvent("database.sqlite.query", {
                            method: "SQLiteDatabase.rawQuery(String, String[], CancellationSignal)",
                            database_path: dbPath,
                            sql: sql,
                            where_args: selectionArgs,
                            cancellation_signal: true
                        });
                    }

                    return original.call(this, sql, selectionArgsArray, cancellationSignal);
                }
            );
        }

        // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable, CancellationSignal cancellationSignal)
        const rawQueryWithFactory_full_cancel = safeOverload(
            sqliteDatabase.rawQueryWithFactory,
            "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String,CancellationSignal]",
            'android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal'
        );
        if (rawQueryWithFactory_full_cancel) {
            rawQueryWithFactory_full_cancel.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String,CancellationSignal]",
                rawQueryWithFactory_full_cancel,
                function (original, factory: any, sql: string, selectionArgsArray: any, editTable: string, cancellationSignal: any) {
                    const type = "\x1b[1;34mevent_type: SQLiteRawQuery\x1b[0m";
                    const methodVal = "SQLiteDatabase.rawQueryWithFactory";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let argsStr = "";
                        if (selectionArgsArray && selectionArgsArray.length > 0) {
                            for (let i = 0; i < selectionArgsArray.length; i++) {
                                argsStr += "\n    - [" + i + "] " + selectionArgsArray[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nSQL Query: " + '\x1b[36m' + sql + '\x1b[0m' +
                            "\nEdit table: " + '\x1b[35m' + (editTable ? editTable : "null") + '\x1b[0m' +
                            "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") +
                            "\nWith factory: " + '\x1b[32m' + (factory ? "Custom factory" : "null") + '\x1b[0m' +
                            "\nWith cancellation signal: " + '\x1b[90m' + "true" + '\x1b[0m' + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, factory, sql, selectionArgsArray, editTable, cancellationSignal);
                }
            );
        }

        // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable)
        const rawQueryWithFactory_full = safeOverload(
            sqliteDatabase.rawQueryWithFactory,
            "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String]",
            'android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String'
        );
        if (rawQueryWithFactory_full) {
            rawQueryWithFactory_full.implementation = safeImplementation(
                "database:SQLiteDatabase.rawQueryWithFactory[CursorFactory,String,String[],String]",
                rawQueryWithFactory_full,
                function (original, factory: any, sql: string, selectionArgsArray: any, editTable: string) {
                    const type = "\x1b[1;34mevent_type: SQLiteRawQuery\x1b[0m";
                    const methodVal = "SQLiteDatabase.rawQueryWithFactory";

                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        let argsStr = "";
                        if (selectionArgsArray && selectionArgsArray.length > 0) {
                            for (let i = 0; i < selectionArgsArray.length; i++) {
                                argsStr += "\n    - [" + i + "] " + selectionArgsArray[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nSQL Query: " + '\x1b[36m' + sql + '\x1b[0m' +
                            "\nEdit table: " + '\x1b[35m' + (editTable ? editTable : "null") + '\x1b[0m' +
                            "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") +
                            "\nWith factory: " + '\x1b[32m' + (factory ? "Custom factory" : "null") + '\x1b[0m' + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, factory, sql, selectionArgsArray, editTable);
                }
            );
        }

        // insert(String table, String nullColumnHack, ContentValues values)
        const insert_String_String_ContentValues = safeOverload(
            sqliteDatabase.insert,
            "database:SQLiteDatabase.insert[String,String,ContentValues]",
            'java.lang.String', 'java.lang.String', 'android.content.ContentValues'
        );
        if (insert_String_String_ContentValues) {
            insert_String_String_ContentValues.implementation = safeImplementation(
                "database:SQLiteDatabase.insert[String,String,ContentValues]",
                insert_String_String_ContentValues,
                function (original, table: string, nullColumnHack: string, values: any) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const contentValues: any = {};
                        if (values) {
                            const keyset = values.keySet();
                            const iter = keyset.iterator();
                            while (iter.hasNext()) {
                                const key = iter.next();
                                const value = values.get(key);
                                contentValues[key] = value;
                            }
                        }

                        createDatabaseEvent("database.sqlite.insert", {
                            method: "SQLiteDatabase.insert(String, String, ContentValues)",
                            database_path: dbPath,
                            table: table,
                            null_column_hack: nullColumnHack,
                            content_values: contentValues
                        });
                    }

                    return original.call(this, table, nullColumnHack, values);
                }
            );
        }

        // insertOrThrow(String table, String nullColumnHack, ContentValues values)
        const insertOrThrow_String_String_ContentValues = safeOverload(
            sqliteDatabase.insertOrThrow,
            "database:SQLiteDatabase.insertOrThrow[String,String,ContentValues]",
            'java.lang.String', 'java.lang.String', 'android.content.ContentValues'
        );
        if (insertOrThrow_String_String_ContentValues) {
            insertOrThrow_String_String_ContentValues.implementation = safeImplementation(
                "database:SQLiteDatabase.insertOrThrow[String,String,ContentValues]",
                insertOrThrow_String_String_ContentValues,
                function (original, table: string, nullColumnHack: string, values: any) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const contentValues: any = {};
                        if (values) {
                            const keyset = values.keySet();
                            const iter = keyset.iterator();
                            while (iter.hasNext()) {
                                const key = iter.next();
                                const value = values.get(key);
                                contentValues[key] = value;
                            }
                        }

                        createDatabaseEvent("database.sqlite.insert", {
                            method: "SQLiteDatabase.insertOrThrow(String, String, ContentValues)",
                            database_path: dbPath,
                            table: table,
                            null_column_hack: nullColumnHack,
                            content_values: contentValues,
                            throw_on_error: true
                        });
                    }

                    return original.call(this, table, nullColumnHack, values);
                }
            );
        }

        // insertWithOnConflict(String table, String nullColumnHack, ContentValues initialValues, int conflictAlgorithm)
        const insertWithOnConflict = safeOverload(
            sqliteDatabase.insertWithOnConflict,
            "database:SQLiteDatabase.insertWithOnConflict[String,String,ContentValues,int]",
            'java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int'
        );
        if (insertWithOnConflict) {
            insertWithOnConflict.implementation = safeImplementation(
                "database:SQLiteDatabase.insertWithOnConflict[String,String,ContentValues,int]",
                insertWithOnConflict,
                function (original, table: string, nullColumnHack: string, values: any, conflictAlgorithm: number) {
                    const type = "\x1b[1;33mevent_type: SQLiteInsert\x1b[0m";
                    const methodVal = "SQLiteDatabase.insertWithOnConflict";

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
                            "\nInsert (with conflict handling) into table: " + '\x1b[36m' + table + '\x1b[0m' +
                            "\nNull column hack: " + '\x1b[35m' + (nullColumnHack ? nullColumnHack : "null") + '\x1b[0m' +
                            "\nValues to insert:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") +
                            "\nConflict algorithm: " + '\x1b[34m' + conflictAlgorithm + '\x1b[0m' + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, table, nullColumnHack, values, conflictAlgorithm);
                }
            );
        }

        // Helper function to interpret database flags
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

        // openDatabase(String path, SQLiteDatabase.CursorFactory factory, int flags)
        const openDatabase_String_CursorFactory_int = safeOverload(
            sqliteDatabase.openDatabase,
            "database:SQLiteDatabase.openDatabase[String,CursorFactory,int]",
            'java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int'
        );
        if (openDatabase_String_CursorFactory_int) {
            openDatabase_String_CursorFactory_int.implementation = safeImplementation(
                "database:SQLiteDatabase.openDatabase[String,CursorFactory,int]",
                openDatabase_String_CursorFactory_int,
                function (original, path: string, factory: any, flags: number) {
                    if (shouldLogDatabasePath(path)) {
                        const flagsDescription = interpretDatabaseFlags(flags);
                        createDatabaseEvent("database.sqlite.open", {
                            method: "SQLiteDatabase.openDatabase(String, CursorFactory, int)",
                            database_path: path,
                            flags: flags,
                            flags_description: flagsDescription,
                            has_factory: factory !== null
                        });
                    }

                    return original.call(this, path, factory, flags);
                }
            );
        }

        // openDatabase(String path, SQLiteDatabase.CursorFactory factory, int flags, DatabaseErrorHandler errorHandler)
        const openDatabase_String_CursorFactory_int_ErrorHandler = safeOverload(
            sqliteDatabase.openDatabase,
            "database:SQLiteDatabase.openDatabase[String,CursorFactory,int,DatabaseErrorHandler]",
            'java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int', 'android.database.DatabaseErrorHandler'
        );
        if (openDatabase_String_CursorFactory_int_ErrorHandler) {
            openDatabase_String_CursorFactory_int_ErrorHandler.implementation = safeImplementation(
                "database:SQLiteDatabase.openDatabase[String,CursorFactory,int,DatabaseErrorHandler]",
                openDatabase_String_CursorFactory_int_ErrorHandler,
                function (original, path: string, factory: any, flags: number, errorHandler: any) {
                    const type = "\x1b[1;36mevent_type: SQLiteOpenDatabase\x1b[0m";
                    const methodVal = "SQLiteDatabase.openDatabase";

                    if (shouldLogDatabasePath(path)) {
                        const flagsDescription = interpretDatabaseFlags(flags);
                        const logVal =
                            "\nOpening database: " + '\x1b[36m' + path + '\x1b[0m' +
                            "\nFlags: " + '\x1b[33m' + flags + " (" + flagsDescription + ")" + '\x1b[0m' +
                            "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') +
                            "\nError handler: " + (errorHandler ? '\x1b[35m' + "Custom error handler provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, path, factory, flags, errorHandler);
                }
            );
        }

        // openOrCreateDatabase(String path, CursorFactory factory)
        const openOrCreateDatabase_String_CursorFactory = safeOverload(
            sqliteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory]",
            'java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory'
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

        // openOrCreateDatabase(String path, CursorFactory factory, DatabaseErrorHandler errorHandler)
        const openOrCreateDatabase_String_CursorFactory_ErrorHandler = safeOverload(
            sqliteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory,DatabaseErrorHandler]",
            'java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'android.database.DatabaseErrorHandler'
        );
        if (openOrCreateDatabase_String_CursorFactory_ErrorHandler) {
            openOrCreateDatabase_String_CursorFactory_ErrorHandler.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[String,CursorFactory,DatabaseErrorHandler]",
                openOrCreateDatabase_String_CursorFactory_ErrorHandler,
                function (original, path: string, factory: any, errorHandler: any) {
                    const type = "\x1b[1;36mevent_type: SQLiteOpenDatabase\x1b[0m";
                    const methodVal = "SQLiteDatabase.openOrCreateDatabase";

                    if (shouldLogDatabasePath(path)) {
                        const logVal =
                            "\nOpening or creating database: " + '\x1b[36m' + path + '\x1b[0m' +
                            "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') +
                            "\nError handler: " + (errorHandler ? '\x1b[35m' + "Custom error handler provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, path, factory, errorHandler);
                }
            );
        }

        // update(String table, ContentValues values, String whereClause, String[] whereArgs)
        const update_String_ContentValues_String_StringArray = safeOverload(
            sqliteDatabase.update,
            "database:SQLiteDatabase.update[String,ContentValues,String,String[]]",
            'java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;'
        );
        if (update_String_ContentValues_String_StringArray) {
            update_String_ContentValues_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.update[String,ContentValues,String,String[]]",
                update_String_ContentValues_String_StringArray,
                function (original, table: string, values: any, whereClause: string, whereArgsArray: any) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    if (shouldLogDatabasePath(dbPath)) {
                        const contentValues: any = {};
                        if (values) {
                            const keyset = values.keySet();
                            const iter = keyset.iterator();
                            while (iter.hasNext()) {
                                const key = iter.next();
                                const value = values.get(key);
                                contentValues[key] = value;
                            }
                        }

                        const whereArgs: string[] = [];
                        if (whereArgsArray && whereArgsArray.length > 0) {
                            for (let i = 0; i < whereArgsArray.length; i++) {
                                whereArgs.push(whereArgsArray[i]);
                            }
                        }

                        createDatabaseEvent("database.sqlite.update", {
                            method: "SQLiteDatabase.update(String, ContentValues, String, String[])",
                            database_path: dbPath,
                            table: table,
                            content_values: contentValues,
                            where_clause: whereClause,
                            where_args: whereArgs
                        });
                    }

                    return original.call(this, table, values, whereClause, whereArgsArray);
                }
            );
        }

        // updateWithOnConflict(String table, ContentValues values, String whereClause, String[] whereArgs, int conflictAlgorithm)
        const updateWithOnConflict = safeOverload(
            sqliteDatabase.updateWithOnConflict,
            "database:SQLiteDatabase.updateWithOnConflict[String,ContentValues,String,String[],int]",
            'java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int'
        );
        if (updateWithOnConflict) {
            updateWithOnConflict.implementation = safeImplementation(
                "database:SQLiteDatabase.updateWithOnConflict[String,ContentValues,String,String[],int]",
                updateWithOnConflict,
                function (original, table: string, values: any, whereClause: string, whereArgsArray: any, conflictAlgorithm: number) {
                    const type = "\x1b[1;32mevent_type: SQLiteUpdate\x1b[0m";
                    const methodVal = "SQLiteDatabase.updateWithOnConflict";

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
                        if (whereArgsArray && whereArgsArray.length > 0) {
                            for (let i = 0; i < whereArgsArray.length; i++) {
                                whereArgsStr += "\n    - [" + i + "] " + whereArgsArray[i];
                            }
                        }

                        const logVal =
                            "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                            "\nUpdate table: " + '\x1b[36m' + table + '\x1b[0m' +
                            "\nWhere clause: " + '\x1b[35m' + whereClause + '\x1b[0m' +
                            "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") +
                            "\nValues to update:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") +
                            "\nConflict algorithm: " + '\x1b[34m' + conflictAlgorithm + '\x1b[0m' + "\n";

                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }

                    return original.call(this, table, values, whereClause, whereArgsArray, conflictAlgorithm);
                }
            );
        }

        // delete(String table, String whereClause, String[] whereArgs)
        const delete_String_String_StringArray = safeOverload(
            sqliteDatabase.delete,
            "database:SQLiteDatabase.delete[String,String,String[]]",
            'java.lang.String', 'java.lang.String', '[Ljava.lang.String;'
        );
        if (delete_String_String_StringArray) {
            delete_String_String_StringArray.implementation = safeImplementation(
                "database:SQLiteDatabase.delete[String,String,String[]]",
                delete_String_String_StringArray,
                function (original, table: string, whereClause: string, whereArgsArray: any) {
                    let dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }

                    let deleteRes: number = 0;

                    if (shouldLogDatabasePath(dbPath)) {
                        const whereArgs: string[] = [];
                        if (whereArgsArray && whereArgsArray.length > 0) {
                            for (let i = 0; i < whereArgsArray.length; i++) {
                                whereArgs.push(whereArgsArray[i]);
                            }
                        }

                        createDatabaseEvent("database.sqlite.delete", {
                            method: "SQLiteDatabase.delete(String, String, String[])",
                            database_path: dbPath,
                            table: table,
                            where_clause: whereClause,
                            where_args: whereArgs
                        });

                        deleteRes = original.call(this, table, whereClause, whereArgsArray);

                        createDatabaseEvent("database.sqlite.delete_result", {
                            method: "SQLiteDatabase.delete(String, String, String[])",
                            database_path: dbPath,
                            table: table,
                            rows_affected: deleteRes
                        });
                    } else {
                        deleteRes = original.call(this, table, whereClause, whereArgsArray);
                    }

                    return deleteRes;
                }
            );
        }

    });
}

function hook_SQLCipher() {
    safePerform("database:hook_SQLCipher", () => {
        const SQLiteOpenHelper = safeUse(
            'net.sqlcipher.database.SQLiteOpenHelper',
            "database:hook_SQLCipher"
        );
        if (SQLiteOpenHelper) {
            const getWritableDatabaseRef = safeOverload(
                SQLiteOpenHelper.getWritableDatabase,
                "database:SQLiteOpenHelper.getWritableDatabase[String]",
                'java.lang.String'
            );
            if (getWritableDatabaseRef) {
                getWritableDatabaseRef.implementation = safeImplementation(
                    "database:SQLiteOpenHelper.getWritableDatabase[String]",
                    getWritableDatabaseRef,
                    function (original, password: string) {
                        createDatabaseEvent("database.sqlcipher.open", {
                            method: "SQLiteOpenHelper.getWritableDatabase(String)",
                            password: password,
                            database_type: "SQLCipher",
                            access_type: "writable"
                        });
                        return original.call(this, password);
                    }
                );
            }
        }

        const SQLiteDatabase = safeUse(
            "net.sqlcipher.database.SQLiteDatabase",
            "database:hook_SQLCipher"
        );
        if (!SQLiteDatabase) {
            return;
        }

        // First openOrCreateDatabase(File, String) – creates event
        const openOrCreate_File_String_event = safeOverload(
            SQLiteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[File,String]",
            "java.io.File",
            "java.lang.String"
        );
        if (openOrCreate_File_String_event) {
            openOrCreate_File_String_event.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[File,String]",
                openOrCreate_File_String_event,
                function (original, file: any, password: string) {
                    createDatabaseEvent("database.sqlcipher.open", {
                        method: "SQLiteDatabase.openOrCreateDatabase(File, String)",
                        database_path: file.getAbsolutePath(),
                        password: password,
                        database_type: "SQLCipher",
                        create_if_necessary: true
                    });
                    return original.call(this, file, password);
                }
            );
        }

        // Utility function to log and send events
        const sendLog = (eventType, methodName, logMessage) => {
            const log = `event_type: ${eventType}, method: ${methodName}, ${logMessage}`;
            am_send(PROFILE_HOOKING_TYPE, log);
        };

        // Second openOrCreateDatabase(File, String) – console log
        const openOrCreate_File_String_log = safeOverload(
            SQLiteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[File,String]_log",
            "java.io.File",
            "java.lang.String"
        );
        if (openOrCreate_File_String_log) {
            openOrCreate_File_String_log.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[File,String]_log",
                openOrCreate_File_String_log,
                function (original, file: any, password: string) {
                    const method = "openOrCreateDatabase(File, String)";
                    sendLog(
                        "SQLCipher.database.SQLiteDatabase",
                        method,
                        `Accessing SQLCipher database at ${file.getAbsolutePath()} with password: ${password}`
                    );
                    return original.call(this, file, password);
                }
            );
        }

        // Hook SQLiteDatabase.openOrCreateDatabase(String, char[])
        const openOrCreate_String_charArray = safeOverload(
            SQLiteDatabase.openOrCreateDatabase,
            "database:SQLiteDatabase.openOrCreateDatabase[String,char[]]",
            "java.lang.String",
            "[C"
        );
        if (openOrCreate_String_charArray) {
            openOrCreate_String_charArray.implementation = safeImplementation(
                "database:SQLiteDatabase.openOrCreateDatabase[String,char[]]",
                openOrCreate_String_charArray,
                function (original, path: string, password: any) {
                    const method = "openOrCreateDatabase(String, char[])";
                    const passwordStr = password ? Java.array("char", password).join("") : "null";
                    sendLog(
                        "SQLCipher.database.SQLiteDatabase",
                        method,
                        `Accessing SQLCipher database at ${path} with password: ${passwordStr}`
                    );
                    return original.call(this, path, password);
                }
            );
        }

        // Hook SQLiteDatabase.rawExecSQL(String)
        const rawExecSQL_String = safeOverload(
            SQLiteDatabase.rawExecSQL,
            "database:SQLiteDatabase.rawExecSQL[String]",
            "java.lang.String"
        );
        if (rawExecSQL_String) {
            rawExecSQL_String.implementation = safeImplementation(
                "database:SQLiteDatabase.rawExecSQL[String]",
                rawExecSQL_String,
                function (original, sql: string) {
                    const method = "rawExecSQL(String)";
                    sendLog(
                        "SQLCipher.database.SQLiteDatabase",
                        method,
                        `Executing raw SQL: ${sql}`
                    );
                    return original.call(this, sql);
                }
            );
        }

        // Hook SQLiteDatabase.execSQL(String)
        const execSQL_String_SQLCipher = safeOverload(
            SQLiteDatabase.execSQL,
            "database:SQLiteDatabase.execSQL[String]_SQLCipher",
            "java.lang.String"
        );
        if (execSQL_String_SQLCipher) {
            execSQL_String_SQLCipher.implementation = safeImplementation(
                "database:SQLiteDatabase.execSQL[String]_SQLCipher",
                execSQL_String_SQLCipher,
                function (original, sql: string) {
                    createDatabaseEvent("database.sqlcipher.exec", {
                        method: "SQLiteDatabase.execSQL(String)",
                        sql: sql,
                        database_type: "SQLCipher"
                    });
                    return original.call(this, sql);
                }
            );
        }

        // Hook SQLiteDatabase.getWritableDatabase(String)
        const getWritableDatabase_String = safeOverload(
            SQLiteDatabase.getWritableDatabase,
            "database:SQLiteDatabase.getWritableDatabase[String]",
            "java.lang.String"
        );
        if (getWritableDatabase_String) {
            getWritableDatabase_String.implementation = safeImplementation(
                "database:SQLiteDatabase.getWritableDatabase[String]",
                getWritableDatabase_String,
                function (original, password: string) {
                    createDatabaseEvent("database.sqlcipher.open", {
                        method: "SQLiteDatabase.getWritableDatabase(String)",
                        password: password,
                        database_type: "SQLCipher",
                        access_type: "writable"
                    });
                    return original.call(this, password);
                }
            );
        }

        // Hook SQLiteDatabase.getReadableDatabase(String)
        const getReadableDatabase_String = safeOverload(
            SQLiteDatabase.getReadableDatabase,
            "database:SQLiteDatabase.getReadableDatabase[String]",
            "java.lang.String"
        );
        if (getReadableDatabase_String) {
            getReadableDatabase_String.implementation = safeImplementation(
                "database:SQLiteDatabase.getReadableDatabase[String]",
                getReadableDatabase_String,
                function (original, password: string) {
                    createDatabaseEvent("database.sqlcipher.open", {
                        method: "SQLiteDatabase.getReadableDatabase(String)",
                        password: password,
                        database_type: "SQLCipher",
                        access_type: "readable"
                    });
                    return original.call(this, password);
                }
            );
        }

        // Hook SQLiteDatabase.close()
        const closeRef = SQLiteDatabase.close;
        if (closeRef) {
            closeRef.implementation = safeImplementation(
                "database:SQLiteDatabase.close",
                closeRef,
                function (original) {
                    const method = "close()";
                    sendLog(
                        "SQLCipher.database.SQLiteDatabase",
                        method,
                        "Closing SQLCipher database"
                    );
                    return original.call(this);
                }
            );
        }

        // Hook SQLiteDatabase.beginTransaction()
        const beginTransactionRef = SQLiteDatabase.beginTransaction;
        if (beginTransactionRef) {
            beginTransactionRef.implementation = safeImplementation(
                "database:SQLiteDatabase.beginTransaction",
                beginTransactionRef,
                function (original) {
                    createDatabaseEvent("database.sqlcipher.transaction", {
                        method: "SQLiteDatabase.beginTransaction()",
                        database_type: "SQLCipher",
                        transaction_action: "begin"
                    });
                    return original.call(this);
                }
            );
        }

        // Hook SQLiteDatabase.endTransaction()
        const endTransactionRef = SQLiteDatabase.endTransaction;
        if (endTransactionRef) {
            endTransactionRef.implementation = safeImplementation(
                "database:SQLiteDatabase.endTransaction",
                endTransactionRef,
                function (original) {
                    createDatabaseEvent("database.sqlcipher.transaction", {
                        method: "SQLiteDatabase.endTransaction()",
                        database_type: "SQLCipher",
                        transaction_action: "end"
                    });
                    return original.call(this);
                }
            );
        }
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

        // Hook SQLiteDatabase.openOrCreateDatabase (only if SQLCipher is present)
        const SQLiteDatabase = safeUse(
            "net.sqlcipher.database.SQLiteDatabase",
            "database:hook_room_library"
        );
        if (SQLiteDatabase) {
            const openOrCreate_File_String = safeOverload(
                SQLiteDatabase.openOrCreateDatabase,
                "database:SQLiteDatabase.openOrCreateDatabase[File,String]_Room",
                "java.io.File",
                "java.lang.String"
            );
            if (openOrCreate_File_String) {
                openOrCreate_File_String.implementation = safeImplementation(
                    "database:SQLiteDatabase.openOrCreateDatabase[File,String]_Room",
                    openOrCreate_File_String,
                    function (original, file: any, password: string) {
                        const methodVal = "SQLiteDatabase.openOrCreateDatabase(File, String), ";
                        const logVal = `Opening or creating database with file: ${file.getAbsolutePath()} and password: ${password}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
                        //console.log(logVal);
                        return original.call(this, file, password);
                    }
                );
            }

            const openOrCreate_String_String = safeOverload(
                SQLiteDatabase.openOrCreateDatabase,
                "database:SQLiteDatabase.openOrCreateDatabase[String,String]_Room",
                "java.lang.String",
                "java.lang.String"
            );
            if (openOrCreate_String_String) {
                openOrCreate_String_String.implementation = safeImplementation(
                    "database:SQLiteDatabase.openOrCreateDatabase[String,String]_Room",
                    openOrCreate_String_String,
                    function (original, path: string, password: string) {
                        const methodVal = "SQLiteDatabase.openOrCreateDatabase(String, String), ";
                        const logVal = `Opening or creating database with path: ${path} and password: ${password}`;
                        am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
                        //console.log(logVal);
                        return original.call(this, path, password);
                    }
                );
            }

            // Hook PRAGMA key setting for SQLCipher
            const execSQL_String_SQLCipherRoom = safeOverload(
                SQLiteDatabase.execSQL,
                "database:SQLiteDatabase.execSQL[String]_Room_SQLCipherPragma",
                "java.lang.String"
            );
            if (execSQL_String_SQLCipherRoom) {
                execSQL_String_SQLCipherRoom.implementation = safeImplementation(
                    "database:SQLiteDatabase.execSQL[String]_Room_SQLCipherPragma",
                    execSQL_String_SQLCipherRoom,
                    function (original, sql: string) {
                        if (sql.toLowerCase().includes("pragma key")) {
                            createDatabaseEvent("database.sqlcipher.pragma", {
                                method: "SQLiteDatabase.execSQL(String)",
                                sql: sql,
                                pragma_type: "key",
                                database_type: "SQLCipher"
                            });
                        }
                        return original.call(this, sql);
                    }
                );
            }
        } // End if (SQLiteDatabase)

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