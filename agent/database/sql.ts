import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java, safeJavaUse } from "../utils/javalib.js"

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



function hook_java_sql(){
    setImmediate(function() {
        Java.perform(function() {
            var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
            // execSQL(String sql)
            sqliteDatabase.execSQL.overload('java.lang.String').implementation = function(var0) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    createDatabaseEvent("database.sqlite.exec", {
                        method: "SQLiteDatabase.execSQL(String)",
                        database_path: dbPath,
                        sql: var0
                    });
                }
                
                var execSQLRes = this.execSQL(var0);
                return execSQLRes;
            };
            
            // execSQL(String sql, Object[] bindArgs)
            sqliteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(var0, var1) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert bind arguments to array
                    var bindArgs = [];
                    if (var1 && var1.length > 0) {
                        for (var i = 0; i < var1.length; i++) {
                            bindArgs.push(var1[i]);
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.exec", {
                        method: "SQLiteDatabase.execSQL(String, Object[])",
                        database_path: dbPath,
                        sql: var0,
                        bind_args: bindArgs
                    });
                }
                
                var execSQLRes = this.execSQL(var0, var1);
                return execSQLRes;
            };
    
            // query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
              sqliteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8) {
                var methodVal = "SQLiteDatabase.query called.";
                var logVal = "Table: " + var1 + ", selection value: " + var3 + ", selectionArgs: " + var4 + " distinct: " + var0;
                am_send(PROFILE_HOOKING_TYPE,methodVal + " " + logVal + "\n");
                var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8);
                return queryRes;
            };
    
    
              // query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
              sqliteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7) {
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert columns and selectionArgs to arrays
                    var columns = var1 ? Array.prototype.slice.call(var1) : [];
                    var selectionArgs = var3 ? Array.prototype.slice.call(var3) : [];
                    
                    createDatabaseEvent("database.sqlite.query", {
                        method: "SQLiteDatabase.query(String, String[], String, String[], String, String, String, String)",
                        database_path: dbPath,
                        table: var0,
                        columns: columns,
                        where_clause: var2,
                        where_args: selectionArgs,
                        group_by: var4,
                        having: var5,
                        order_by: var6,
                        limit: var7
                    });
                }
                
                var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7);
                return queryRes;
            };
    
               // query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
               sqliteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
                var methodVal = "SQLiteDatabase.query called.";
                var logVal = "Table: " + var1 + ", selection value: " + var3 + ", selectionArgs: " + var4;
                am_send(PROFILE_HOOKING_TYPE,methodVal + " " + logVal + "\n");
                var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
                return queryRes;
            };
    
               // query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy)
              sqliteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6) {
                var methodVal = "SQLiteDatabase.query called.";
                var logVal = "Table: " + var0 + ", selection value: " + var2 + ", selectionArgs: " + var3;
                am_send(PROFILE_HOOKING_TYPE,methodVal + " " + logVal + "\n");
                var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6);
                return queryRes;
            };
    
               // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
              sqliteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
                var methodVal = "SQLiteDatabase.queryWithFactory called.";
                var logVal = "Table: " + var2 + ", selection value: " + var4 + ", selectionArgs: " + var5 + " distinct: " + var1;
                am_send(PROFILE_HOOKING_TYPE,methodVal + " " + logVal + "\n");
                var queryWithFactoryRes = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
                return queryWithFactoryRes;
            };   		
    
               // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
              sqliteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10) {
                var methodVal = "SQLiteDatabase.queryWithFactory called.";
                var logVal = "Table: " + var2 + ", selection value: " + var4 + ", selectionArgs: " + var5 + " distinct: " + var1;
                am_send(PROFILE_HOOKING_TYPE,methodVal + " " + logVal + "\n");
                var queryWithFactoryRes = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10);
                return queryWithFactoryRes;
            }; 
    
            // rawQuery(String sql, String[] selectionArgs) 
            sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(var0, var1) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert selection args to array
                    var selectionArgs = [];
                    if (var1 && var1.length > 0) {
                        for (var i = 0; i < var1.length; i++) {
                            selectionArgs.push(var1[i]);
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.query", {
                        method: "SQLiteDatabase.rawQuery(String, String[])",
                        database_path: dbPath,
                        sql: var0,
                        where_args: selectionArgs
                    });
                }
                
                var rawQueryRes = this.rawQuery(var0, var1);
                return rawQueryRes;
            };
    
            // rawQuery(String sql, String[] selectionArgs, CancellationSignal cancellationSignal)
            sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal').implementation = function(var0, var1, var2) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert selection args to array
                    var selectionArgs = [];
                    if (var1 && var1.length > 0) {
                        for (var i = 0; i < var1.length; i++) {
                            selectionArgs.push(var1[i]);
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.query", {
                        method: "SQLiteDatabase.rawQuery(String, String[], CancellationSignal)",
                        database_path: dbPath,
                        sql: var0,
                        where_args: selectionArgs,
                        cancellation_signal: true
                    });
                }
                
                var rawQueryRes = this.rawQuery(var0, var1, var2);
                return rawQueryRes;
            };
    
            // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable, CancellationSignal cancellationSignal)
            sqliteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4) {
                var type = "\x1b[1;34mevent_type: SQLiteRawQuery\x1b[0m";
                var methodVal = "SQLiteDatabase.rawQueryWithFactory";
                
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Format selection args properly
                    var argsStr = "";
                    if (var2 && var2.length > 0) {
                        for (var i = 0; i < var2.length; i++) {
                            argsStr += "\n    - [" + i + "] " + var2[i];
                        }
                    }
                    
                    var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                 "\nSQL Query: " + '\x1b[36m' + var1 + '\x1b[0m' + 
                                 "\nEdit table: " + '\x1b[35m' + (var3 ? var3 : "null") + '\x1b[0m' +
                                 "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") +
                                 "\nWith factory: " + '\x1b[32m' + (var0 ? "Custom factory" : "null") + '\x1b[0m' +
                                 "\nWith cancellation signal: " + '\x1b[90m' + "true" + '\x1b[0m' + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var rawQueryWithFactoryRes = this.rawQueryWithFactory(var0, var1, var2, var3, var4);
                return rawQueryWithFactoryRes;
            };
    
            // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable)
            sqliteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(var0, var1, var2, var3) {
                var type = "\x1b[1;34mevent_type: SQLiteRawQuery\x1b[0m";
                var methodVal = "SQLiteDatabase.rawQueryWithFactory";
                
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Format selection args properly
                    var argsStr = "";
                    if (var2 && var2.length > 0) {
                        for (var i = 0; i < var2.length; i++) {
                            argsStr += "\n    - [" + i + "] " + var2[i];
                        }
                    }
                    
                    var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                 "\nSQL Query: " + '\x1b[36m' + var1 + '\x1b[0m' + 
                                 "\nEdit table: " + '\x1b[35m' + (var3 ? var3 : "null") + '\x1b[0m' +
                                 "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") +
                                 "\nWith factory: " + '\x1b[32m' + (var0 ? "Custom factory" : "null") + '\x1b[0m' + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var rawQueryWithFactoryRes = this.rawQueryWithFactory(var0, var1, var2, var3);
                return rawQueryWithFactoryRes;
            };
    
            // insert(String table, String nullColumnHack, ContentValues values)
            sqliteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(var0, var1, var2) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert ContentValues to object
                    var contentValues = {};
                    if (var2) {
                        var keyset = var2.keySet();
                        var iter = keyset.iterator();
                        while(iter.hasNext()) {
                            var key = iter.next();
                            var value = var2.get(key);
                            contentValues[key] = value;
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.insert", {
                        method: "SQLiteDatabase.insert(String, String, ContentValues)",
                        database_path: dbPath,
                        table: var0,
                        null_column_hack: var1,
                        content_values: contentValues
                    });
                }
                var insertValueRes = this.insert(var0, var1, var2);
                return insertValueRes;
            };

            // insertOrThrow(String table, String nullColumnHack, ContentValues values)
            sqliteDatabase.insertOrThrow.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(var0, var1, var2) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert ContentValues to object
                    var contentValues = {};
                    if (var2) {
                        var keyset = var2.keySet();
                        var iter = keyset.iterator();
                        while(iter.hasNext()) {
                            var key = iter.next();
                            var value = var2.get(key);
                            contentValues[key] = value;
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.insert", {
                        method: "SQLiteDatabase.insertOrThrow(String, String, ContentValues)",
                        database_path: dbPath,
                        table: var0,
                        null_column_hack: var1,
                        content_values: contentValues,
                        throw_on_error: true
                    });
                }
                
                var insertValueRes = this.insertOrThrow(var0, var1, var2);
                return insertValueRes;
            };

            // insertWithOnConflict(String table, String nullColumnHack, ContentValues initialValues, int conflictAlgorithm)
            sqliteDatabase.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int').implementation = function(var0, var1, var2, var3) {
                var type = "\x1b[1;33mevent_type: SQLiteInsert\x1b[0m";
                var methodVal = "SQLiteDatabase.insertWithOnConflict";
                
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Format ContentValues properly
                    var valuesStr = "";
                    if (var2) {
                        var keyset = var2.keySet();
                        var iter = keyset.iterator();
                        while(iter.hasNext()) {
                            var key = iter.next();
                            var value = var2.get(key);
                            valuesStr += "\n    - " + key + " = " + value;
                        }
                    }
                    
                    var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                "\nInsert (with conflict handling) into table: " + '\x1b[36m' + var0 + '\x1b[0m' + 
                                "\nNull column hack: " + '\x1b[35m' + (var1 ? var1 : "null") + '\x1b[0m' + 
                                "\nValues to insert:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") + 
                                "\nConflict algorithm: " + '\x1b[34m' + var3 + '\x1b[0m' + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var insertValueRes = this.insertWithOnConflict(var0, var1, var2, var3);
                return insertValueRes;
            };

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
                
                let flagDescriptions = [];
                for (let flag in flagsMap) {
                    // Convert string to number before bitwise comparison
                    const numericFlag = parseInt(flag);
                    if ((flags & numericFlag) === numericFlag) {
                        flagDescriptions.push(flagsMap[flag]);
                    }
                }
                
                return flagDescriptions.length > 0 ? flagDescriptions.join(" | ") : "UNKNOWN_FLAG";
            }

            // openDatabase(String path, SQLiteDatabase.CursorFactory factory, int flags)
            sqliteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int').implementation = function(path, factory, flags) {
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(path)) {
                    // Interpret the flags
                    var flagsDescription = interpretDatabaseFlags(flags);
                    
                    createDatabaseEvent("database.sqlite.open", {
                        method: "SQLiteDatabase.openDatabase(String, CursorFactory, int)",
                        database_path: path,
                        flags: flags,
                        flags_description: flagsDescription,
                        has_factory: factory !== null
                    });
                }
                
                var dbResult = this.openDatabase(path, factory, flags);
                return dbResult;
            };

            // openDatabase(String path, SQLiteDatabase.CursorFactory factory, int flags, DatabaseErrorHandler errorHandler)
            sqliteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int', 'android.database.DatabaseErrorHandler').implementation = function(path, factory, flags, errorHandler) {
                var type = "\x1b[1;36mevent_type: SQLiteOpenDatabase\x1b[0m";
                var methodVal = "SQLiteDatabase.openDatabase";
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(path)) {
                    // Interpret the flags
                    var flagsDescription = interpretDatabaseFlags(flags);
                    
                    var logVal = "\nOpening database: " + '\x1b[36m' + path + '\x1b[0m' + 
                                    "\nFlags: " + '\x1b[33m' + flags + " (" + flagsDescription + ")" + '\x1b[0m' + 
                                    "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') +
                                    "\nError handler: " + (errorHandler ? '\x1b[35m' + "Custom error handler provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var dbResult = this.openDatabase(path, factory, flags, errorHandler);
                return dbResult;
            };

            // openOrCreateDatabase method hooks
            sqliteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function(path, factory) {
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(path)) {
                    createDatabaseEvent("database.sqlite.open", {
                        method: "SQLiteDatabase.openOrCreateDatabase(String, CursorFactory)",
                        database_path: path,
                        has_factory: factory !== null,
                        create_if_necessary: true
                    });
                }
                
                var dbResult = this.openOrCreateDatabase(path, factory);
                return dbResult;
            };

            // openOrCreateDatabase with error handler
            sqliteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'android.database.DatabaseErrorHandler').implementation = function(path, factory, errorHandler) {
                var type = "\x1b[1;36mevent_type: SQLiteOpenDatabase\x1b[0m";
                var methodVal = "SQLiteDatabase.openOrCreateDatabase";
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(path)) {
                    var logVal = "\nOpening or creating database: " + '\x1b[36m' + path + '\x1b[0m' + 
                                    "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') +
                                    "\nError handler: " + (errorHandler ? '\x1b[35m' + "Custom error handler provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var dbResult = this.openOrCreateDatabase(path, factory, errorHandler);
                return dbResult;
            };

            // update(String table, ContentValues values, String whereClause, String[] whereArgs)
            sqliteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(var0, var1, var2, var3) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert ContentValues to object
                    var contentValues = {};
                    if (var1) {
                        var keyset = var1.keySet();
                        var iter = keyset.iterator();
                        while(iter.hasNext()) {
                            var key = iter.next();
                            var value = var1.get(key);
                            contentValues[key] = value;
                        }
                    }
                    
                    // Convert whereArgs to array
                    var whereArgs = [];
                    if (var3 && var3.length > 0) {
                        for (var i = 0; i < var3.length; i++) {
                            whereArgs.push(var3[i]);
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.update", {
                        method: "SQLiteDatabase.update(String, ContentValues, String, String[])",
                        database_path: dbPath,
                        table: var0,
                        content_values: contentValues,
                        where_clause: var2,
                        where_args: whereArgs
                    });
                }
                
                var updateRes = this.update(var0, var1, var2, var3);
                return updateRes;
            };

            // updateWithOnConflict(String table, ContentValues values, String whereClause, String[] whereArgs, int conflictAlgorithm) 
            sqliteDatabase.updateWithOnConflict.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int').implementation = function(var0, var1, var2, var3, var4) {
                var type = "\x1b[1;32mevent_type: SQLiteUpdate\x1b[0m";
                var methodVal = "SQLiteDatabase.updateWithOnConflict";
                
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Format ContentValues properly
                    var valuesStr = "";
                    if (var1) {
                        var keyset = var1.keySet();
                        var iter = keyset.iterator();
                        while(iter.hasNext()) {
                            var key = iter.next();
                            var value = var1.get(key);
                            valuesStr += "\n    - " + key + " = " + value;
                        }
                    }
                    
                    // Format whereArgs properly
                    var whereArgsStr = "";
                    if (var3 && var3.length > 0) {
                        for (var i = 0; i < var3.length; i++) {
                            whereArgsStr += "\n    - [" + i + "] " + var3[i];
                        }
                    }
                    
                    var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                "\nUpdate table: " + '\x1b[36m' + var0 + '\x1b[0m' + 
                                "\nWhere clause: " + '\x1b[35m' + var2 + '\x1b[0m' + 
                                "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") + 
                                "\nValues to update:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") +
                                "\nConflict algorithm: " + '\x1b[34m' + var4 + '\x1b[0m' + "\n";
                    
                    am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                }
                
                var updateRes = this.updateWithOnConflict(var0, var1, var2, var3, var4);
                return updateRes;
            };

            // delete(String table, String whereClause, String[] whereArgs)
            sqliteDatabase.delete.overload('java.lang.String', 'java.lang.String', '[Ljava.lang.String;').implementation = function(var0, var1, var2) {
                // Get database path
                var dbPath = "unknown";
                try {
                    dbPath = this.getPath();
                } catch (e) {
                    dbPath = "Error getting path: " + e;
                }
                
                // Only proceed if the database path should be logged
                if (shouldLogDatabasePath(dbPath)) {
                    // Convert whereArgs to array
                    var whereArgs = [];
                    if (var2 && var2.length > 0) {
                        for (var i = 0; i < var2.length; i++) {
                            whereArgs.push(var2[i]);
                        }
                    }
                    
                    createDatabaseEvent("database.sqlite.delete", {
                        method: "SQLiteDatabase.delete(String, String, String[])",
                        database_path: dbPath,
                        table: var0,
                        where_clause: var1,
                        where_args: whereArgs
                    });
                }
                
                var deleteRes = this.delete(var0, var1, var2);
                
                // Log rows affected as a separate event
                if (shouldLogDatabasePath(dbPath)) {
                    createDatabaseEvent("database.sqlite.delete_result", {
                        method: "SQLiteDatabase.delete(String, String, String[])",
                        database_path: dbPath,
                        table: var0,
                        rows_affected: deleteRes
                    });
                }
                
                return deleteRes;
            };

    
        });
    });

}

function hook_SQLCipher() {
    setImmediate(function() {
        Java.perform(function() {
            const SQLiteOpenHelper = safeJavaUse('net.sqlcipher.database.SQLiteOpenHelper');
            if (SQLiteOpenHelper) {
                SQLiteOpenHelper.getWritableDatabase.overload('java.lang.String').implementation = function (password) {
                    createDatabaseEvent("database.sqlcipher.open", {
                        method: "SQLiteOpenHelper.getWritableDatabase(String)",
                        password: password,
                        database_type: "SQLCipher",
                        access_type: "writable"
                    });

                    return this.getWritableDatabase.overload('java.lang.String').apply(this, arguments);
                }
            }

            const SQLiteDatabase = safeJavaUse("net.sqlcipher.database.SQLiteDatabase");
            if (!SQLiteDatabase) {
                return;
            }

            SQLiteDatabase.openOrCreateDatabase.overload(
                "java.io.File",
                "java.lang.String"
            ).implementation = function (file, password) {
                createDatabaseEvent("database.sqlcipher.open", {
                    method: "SQLiteDatabase.openOrCreateDatabase(File, String)",
                    database_path: file.getAbsolutePath(),
                    password: password,
                    database_type: "SQLCipher",
                    create_if_necessary: true
                });

                // Call the original method
                const result = this.openOrCreateDatabase(file, password);
                return result;
            };

                        // Utility function to log and send events
            const sendLog = (eventType, methodName, logMessage) => {
                const log = `event_type: ${eventType}, method: ${methodName}, ${logMessage}`;
                am_send(PROFILE_HOOKING_TYPE,log);
            };

            // Hook SQLiteDatabase.openOrCreateDatabase(File, String) 
            SQLiteDatabase.openOrCreateDatabase.overload(
                "java.io.File",
                "java.lang.String"
            ).implementation = function (file, password) {
                const method = "openOrCreateDatabase(File, String)";
                sendLog(
                "SQLCipher.database.SQLiteDatabase",
                method,
                `Accessing SQLCipher database at ${file.getAbsolutePath()} with password: ${password}`
                );
                return this.openOrCreateDatabase(file, password);
            };

            // Hook SQLiteDatabase.openOrCreateDatabase(String, char[])
            SQLiteDatabase.openOrCreateDatabase.overload(
                "java.lang.String",
                "[C"
            ).implementation = function (path, password) {
                const method = "openOrCreateDatabase(String, char[])";
                const passwordStr = password ? Java.array("char", password).join("") : "null";
                sendLog(
                "SQLCipher.database.SQLiteDatabase",
                method,
                `Accessing SQLCipher database at ${path} with password: ${passwordStr}`
                );
                return this.openOrCreateDatabase(path, password);
            };

            // Hook SQLiteDatabase.rawExecSQL(String)
            SQLiteDatabase.rawExecSQL.overload("java.lang.String").implementation = function (sql) {
                const method = "rawExecSQL(String)";
                sendLog(
                "SQLCipher.database.SQLiteDatabase",
                method,
                `Executing raw SQL: ${sql}`
                );
                return this.rawExecSQL(sql);
            };

            // Hook SQLiteDatabase.execSQL(String)
            SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
                createDatabaseEvent("database.sqlcipher.exec", {
                    method: "SQLiteDatabase.execSQL(String)",
                    sql: sql,
                    database_type: "SQLCipher"
                });
                return this.execSQL(sql);
            };

            // Hook SQLiteDatabase.getWritableDatabase(String)
            SQLiteDatabase.getWritableDatabase.overload("java.lang.String").implementation = function (password) {
                createDatabaseEvent("database.sqlcipher.open", {
                    method: "SQLiteDatabase.getWritableDatabase(String)",
                    password: password,
                    database_type: "SQLCipher",
                    access_type: "writable"
                });
                return this.getWritableDatabase(password);
            };

            // Hook SQLiteDatabase.getReadableDatabase(String)
            SQLiteDatabase.getReadableDatabase.overload("java.lang.String").implementation = function (password) {
                createDatabaseEvent("database.sqlcipher.open", {
                    method: "SQLiteDatabase.getReadableDatabase(String)",
                    password: password,
                    database_type: "SQLCipher",
                    access_type: "readable"
                });
                return this.getReadableDatabase(password);
            };

            // Hook SQLiteDatabase.close()
            SQLiteDatabase.close.implementation = function () {
                const method = "close()";
                sendLog(
                "SQLCipher.database.SQLiteDatabase",
                method,
                "Closing SQLCipher database"
                );
                return this.close();
            };

            // Hook SQLiteDatabase.beginTransaction()
            SQLiteDatabase.beginTransaction.implementation = function () {
                createDatabaseEvent("database.sqlcipher.transaction", {
                    method: "SQLiteDatabase.beginTransaction()",
                    database_type: "SQLCipher",
                    transaction_action: "begin"
                });
                return this.beginTransaction();
            };

            // Hook SQLiteDatabase.endTransaction()
            SQLiteDatabase.endTransaction.implementation = function () {
                createDatabaseEvent("database.sqlcipher.transaction", {
                    method: "SQLiteDatabase.endTransaction()",
                    database_type: "SQLCipher",
                    transaction_action: "end"
                });
                return this.endTransaction();
            };



        });

    });

}


function hook_sql_related_stuff(){

}


function hook_room_library(){
    // the room library is a famous SQL library on Android
    setImmediate(function () {
        Java.perform(function () {
            //console.log("ROOM hooks being installed");

            // Hook the Room.databaseBuilder method
            const Room = safeJavaUse("androidx.room.Room");
            if (!Room) {
                return;
            }

            Room.databaseBuilder.overload("android.content.Context", "java.lang.Class", "java.lang.String").implementation = function (context, klass, dbName) {
                createDatabaseEvent("database.room.builder", {
                    method: "Room.databaseBuilder(Context, Class, String)",
                    database_name: dbName,
                    database_class: klass.toString(),
                    database_type: "Room"
                });

                const result = this.databaseBuilder(context, klass, dbName);
                return result;
            };

            // Hook SQLiteDatabase.openOrCreateDatabase (only if SQLCipher is present)
            const SQLiteDatabase = safeJavaUse("net.sqlcipher.database.SQLiteDatabase");
            if (SQLiteDatabase) {

            SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "java.lang.String").implementation = function (file, password) {
                const methodVal = "SQLiteDatabase.openOrCreateDatabase(File, String), ";
                const logVal = `Opening or creating database with file: ${file.getAbsolutePath()} and password: ${password}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
                //console.log(logVal);
                return this.openOrCreateDatabase(file, password);
            };

            SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "java.lang.String").implementation = function (path, password) {
                const methodVal = "SQLiteDatabase.openOrCreateDatabase(String, String), ";
                const logVal = `Opening or creating database with path: ${path} and password: ${password}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
                //console.log(logVal);
                return this.openOrCreateDatabase(path, password);
            };

            // Hook PRAGMA key setting for SQLCipher
            SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
                if (sql.toLowerCase().includes("pragma key")) {
                    createDatabaseEvent("database.sqlcipher.pragma", {
                        method: "SQLiteDatabase.execSQL(String)",
                        sql: sql,
                        pragma_type: "key",
                        database_type: "SQLCipher"
                    });
                }
                return this.execSQL(sql);
            };
            } // End if (SQLiteDatabase)

            // Hook SupportSQLiteOpenHelper.Callback onCreate
            const SupportSQLiteOpenHelper_Callback = safeJavaUse("androidx.sqlite.db.SupportSQLiteOpenHelper$Callback");
            if (SupportSQLiteOpenHelper_Callback) {

            SupportSQLiteOpenHelper_Callback.onCreate.implementation = function (db) {
                createDatabaseEvent("database.room.callback", {
                    method: "SupportSQLiteOpenHelper.Callback.onCreate(SupportSQLiteDatabase)",
                    database_object: db.toString(),
                    callback_type: "onCreate",
                    database_type: "Room"
                });
                return this.onCreate(db);
            };

            // Hook SupportSQLiteOpenHelper.Callback onOpen
            SupportSQLiteOpenHelper_Callback.onOpen.implementation = function (db) {
                createDatabaseEvent("database.room.callback", {
                    method: "SupportSQLiteOpenHelper.Callback.onOpen(SupportSQLiteDatabase)",
                    database_object: db.toString(),
                    callback_type: "onOpen",
                    database_type: "Room"
                });
                return this.onOpen(db);
            };
            } // End if (SupportSQLiteOpenHelper_Callback)


            // Hook DAO methods (insert, update, delete)
            const Dao = safeJavaUse("androidx.room.RoomDatabase");
            if (Dao) {
            Dao.insert.overload("java.lang.Object").implementation = function (entity) {
                createDatabaseEvent("database.room.dao", {
                    method: "RoomDatabase.insert(Object)",
                    entity: entity.toString(),
                    dao_operation: "insert",
                    database_type: "Room"
                });
                return this.insert(entity);
            };

            Dao.update.overload("java.lang.Object").implementation = function (entity) {
                createDatabaseEvent("database.room.dao", {
                    method: "RoomDatabase.update(Object)",
                    entity: entity.toString(),
                    dao_operation: "update",
                    database_type: "Room"
                });
                return this.update(entity);
            };

            Dao.delete.overload("java.lang.Object").implementation = function (entity) {
                createDatabaseEvent("database.room.dao", {
                    method: "RoomDatabase.delete(Object)",
                    entity: entity.toString(),
                    dao_operation: "delete",
                    database_type: "Room"
                });
                return this.delete(entity);
            };
            } // End if (Dao)

            // Hook query execution (using same Dao reference as RoomDatabase)
            if (Dao) {
            Dao.query.overload("androidx.sqlite.db.SupportSQLiteQuery").implementation = function (query) {
                const methodVal = "RoomDatabase.query, ";
                const logVal = `Query executed: ${query.toString()}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Database, ${methodVal}${logVal}`);
                return this.query(query);
            };
            } // End if (Dao)

            // Hook SupportSQLiteDatabase execSQL
            const SupportSQLiteDatabase = safeJavaUse("androidx.sqlite.db.SupportSQLiteDatabase");
            if (SupportSQLiteDatabase) {
            SupportSQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
                const methodVal = "SupportSQLiteDatabase.execSQL, ";
                const logVal = `Executing SQL: ${sql}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Database, ${methodVal}${logVal}`);
                return this.execSQL(sql);
            };
            } // End if (SupportSQLiteDatabase)

            // Hook LiveData observe
            const LiveData = safeJavaUse("androidx.lifecycle.LiveData");
            if (LiveData) {
            LiveData.observe.overload("androidx.lifecycle.LifecycleOwner", "androidx.lifecycle.Observer").implementation = function (owner, observer) {
                const methodVal = "LiveData.observe, ";
                const logVal = `LiveData observed with LifecycleOwner: ${owner.toString()}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: Room.LiveData, ${methodVal}${logVal}`);
                return this.observe(owner, observer);
            };
            } // End if (LiveData)

            // Hook Flow collect
            const FlowCollector = safeJavaUse("kotlinx.coroutines.flow.FlowCollector");
            if (FlowCollector) {
            FlowCollector.emit.overload("java.lang.Object").implementation = function (value) {
                const methodVal = "FlowCollector.emit, ";
                const logVal = `Flow emitted value: ${value}`;
                am_send(PROFILE_HOOKING_TYPE, `event_type: Room.Flow, ${methodVal}${logVal}`);
                //console.log(logVal);
                return this.emit(value);
            };
            } // End if (FlowCollector)

        });
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
        
        // Helper function to safely hook a native function
        function hookFunction(name, successCallback) {
            try {
                const address = module.findExportByName(name);
                if (address) {
                    successCallback(address);
                    devlog(`✅ Successfully hooked ${name} in ${module.name}`);
                } else {
                    devlog(`⚠️ Could not find export for ${name} in ${module.name}`);
                }
            } catch (error) {
                // Fix: Safely handle the error message property
                const errorMessage = error instanceof Error ? error.message : String(error);
                devlog(`⚠️ Error hooking ${name} in ${module.name}: ${errorMessage}`);
            }
        }
        
        // Hook sqlite3_open and variants
        ["sqlite3_open", "sqlite3_open_v2", "sqlite3_open16"].forEach(funcName => {
            hookFunction(funcName, address => {
                Interceptor.attach(address, {
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
            Interceptor.attach(address, {
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
                Interceptor.attach(address, {
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
            Interceptor.attach(address, {
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
                Interceptor.attach(address, {
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
                Interceptor.attach(address, {
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
    setImmediate(function() {
        Java.perform(function() {
            const wcdbDatabase = safeJavaUse("com.tencent.wcdb.database.SQLiteDatabase");
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
                    
                    let flagDescriptions = [];
                    for (let flag in flagsMap) {
                        const numericFlag = parseInt(flag);
                        if ((flags & numericFlag) === numericFlag) {
                            flagDescriptions.push(flagsMap[flag]);
                        }
                    }
                    
                    return flagDescriptions.length > 0 ? flagDescriptions.join(" | ") : "UNKNOWN_FLAG";
                }
                
                // openDatabase hooks
                wcdbDatabase.openDatabase.overload('java.lang.String', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory', 'int').implementation = function(path, factory, flags) {
                    var type = "\x1b[1;36mevent_type: WCDBOpenDatabase\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.openDatabase";
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(path)) {
                        // Interpret the flags
                        var flagsDescription = interpretDatabaseFlags(flags);
                        
                        var logVal = "\nOpening WCDB database: " + '\x1b[36m' + path + '\x1b[0m' + 
                                       "\nFlags: " + '\x1b[33m' + flags + " (" + flagsDescription + ")" + '\x1b[0m' + 
                                       "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var dbResult = this.openDatabase(path, factory, flags);
                    return dbResult;
                };
                
                // openOrCreateDatabase hooks
                wcdbDatabase.openOrCreateDatabase.overload('java.lang.String', 'com.tencent.wcdb.database.SQLiteDatabase$CursorFactory').implementation = function(path, factory) {
                    var type = "\x1b[1;36mevent_type: WCDBOpenDatabase\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.openOrCreateDatabase";
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(path)) {
                        var logVal = "\nOpening or creating WCDB database: " + '\x1b[36m' + path + '\x1b[0m' + 
                                       "\nFactory: " + (factory ? '\x1b[32m' + "Custom factory provided" + '\x1b[0m' : '\x1b[90m' + "null" + '\x1b[0m') + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var dbResult = this.openOrCreateDatabase(path, factory);
                    return dbResult;
                };
                
                // execSQL hooks
                wcdbDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
                    var type = "\x1b[1;35mevent_type: WCDBExecSQL\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.execSQL";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                     "\nExecuting SQL: " + '\x1b[36m' + sql + '\x1b[0m' + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var execSQLRes = this.execSQL(sql);
                    return execSQLRes;
                };
                
                // execSQL with bindArgs
                wcdbDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(sql, bindArgs) {
                    var type = "\x1b[1;35mevent_type: WCDBExecSQL\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.execSQL";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        // Format bind arguments properly
                        var argsStr = "";
                        if (bindArgs && bindArgs.length > 0) {
                            for (var i = 0; i < bindArgs.length; i++) {
                                argsStr += "\n    - [" + i + "] " + bindArgs[i];
                            }
                        }
                        
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                     "\nExecuting SQL: " + '\x1b[36m' + sql + '\x1b[0m' + 
                                     "\nBind arguments:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var execSQLRes = this.execSQL(sql, bindArgs);
                    return execSQLRes;
                };
                
                // rawQuery hooks
                wcdbDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
                    var type = "\x1b[1;34mevent_type: WCDBRawQuery\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.rawQuery";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        // Format selection args properly
                        var argsStr = "";
                        if (selectionArgs && selectionArgs.length > 0) {
                            for (var i = 0; i < selectionArgs.length; i++) {
                                argsStr += "\n    - [" + i + "] " + selectionArgs[i];
                            }
                        }
                        
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                     "\nSQL Query: " + '\x1b[36m' + sql + '\x1b[0m' + 
                                     "\nSelection args:" + (argsStr ? '\x1b[33m' + argsStr + '\x1b[0m' : " none") + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var rawQueryRes = this.rawQuery(sql, selectionArgs);
                    return rawQueryRes;
                };
                
                // insert hook
                wcdbDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
                    var type = "\x1b[1;33mevent_type: WCDBInsert\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.insert";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        // Format ContentValues properly
                        var valuesStr = "";
                        if (values) {
                            var keyset = values.keySet();
                            var iter = keyset.iterator();
                            while(iter.hasNext()) {
                                var key = iter.next();
                                var value = values.get(key);
                                valuesStr += "\n    - " + key + " = " + value;
                            }
                        }
                        
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nInsert into table: " + '\x1b[36m' + table + '\x1b[0m' + 
                                    "\nNull column hack: " + '\x1b[35m' + (nullColumnHack ? nullColumnHack : "null") + '\x1b[0m' + 
                                    "\nValues to insert:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var insertValueRes = this.insert(table, nullColumnHack, values);
                    return insertValueRes;
                };
                
                // update hook
                wcdbDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(table, values, whereClause, whereArgs) {
                    var type = "\x1b[1;32mevent_type: WCDBUpdate\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.update";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        // Format ContentValues properly
                        var valuesStr = "";
                        if (values) {
                            var keyset = values.keySet();
                            var iter = keyset.iterator();
                            while(iter.hasNext()) {
                                var key = iter.next();
                                var value = values.get(key);
                                valuesStr += "\n    - " + key + " = " + value;
                            }
                        }
                        
                        // Format whereArgs properly
                        var whereArgsStr = "";
                        if (whereArgs && whereArgs.length > 0) {
                            for (var i = 0; i < whereArgs.length; i++) {
                                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
                            }
                        }
                        
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nUpdate table: " + '\x1b[36m' + table + '\x1b[0m' + 
                                    "\nWhere clause: " + '\x1b[35m' + whereClause + '\x1b[0m' + 
                                    "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") + 
                                    "\nValues to update:" + (valuesStr ? '\x1b[32m' + valuesStr + '\x1b[0m' : " none") + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var updateRes = this.update(table, values, whereClause, whereArgs);
                    return updateRes;
                };
                
                // delete hook
                wcdbDatabase.delete.overload('java.lang.String', 'java.lang.String', '[Ljava.lang.String;').implementation = function(table, whereClause, whereArgs) {
                    var type = "\x1b[1;31mevent_type: WCDBDelete\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.delete";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    // Only proceed if the database path should be logged
                    if (shouldLogDatabasePath(dbPath)) {
                        // Format whereArgs properly
                        var whereArgsStr = "";
                        if (whereArgs && whereArgs.length > 0) {
                            for (var i = 0; i < whereArgs.length; i++) {
                                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
                            }
                        }
                        
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nDelete from table: " + '\x1b[36m' + table + '\x1b[0m' + 
                                    "\nWhere clause: " + '\x1b[35m' + (whereClause ? whereClause : "null (delete all rows)") + '\x1b[0m' + 
                                    "\nWhere args:" + (whereArgsStr ? '\x1b[33m' + whereArgsStr + '\x1b[0m' : " none") + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    var deleteRes = this.delete(table, whereClause, whereArgs);
                    
                    // If row count is being logged, you could add it here
                    if (shouldLogDatabasePath(dbPath)) {
                        var rowCountMsg = "Rows affected: " + '\x1b[32m' + deleteRes + '\x1b[0m';
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + " " + rowCountMsg);
                    }
                    
                    return deleteRes;
                };
                
                // Transaction hooks
                wcdbDatabase.beginTransaction.implementation = function() {
                    var type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.beginTransaction";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    if (shouldLogDatabasePath(dbPath)) {
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nBeginning transaction" + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    return this.beginTransaction();
                };
                
                wcdbDatabase.endTransaction.implementation = function() {
                    var type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.endTransaction";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    if (shouldLogDatabasePath(dbPath)) {
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nEnding transaction" + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    return this.endTransaction();
                };
                
                wcdbDatabase.setTransactionSuccessful.implementation = function() {
                    var type = "\x1b[1;90mevent_type: WCDBTransaction\x1b[0m";
                    var methodVal = "WCDB.SQLiteDatabase.setTransactionSuccessful";
                    
                    // Get database path
                    var dbPath = "unknown";
                    try {
                        dbPath = this.getPath();
                    } catch (e) {
                        dbPath = "Error getting path: " + e;
                    }
                    
                    if (shouldLogDatabasePath(dbPath)) {
                        var logVal = "\nDatabase: " + '\x1b[31m' + dbPath + '\x1b[0m' +
                                    "\nMarking transaction as successful" + "\n";
                        
                        am_send(PROFILE_HOOKING_TYPE, type + " " + methodVal + logVal);
                    }
                    
                    return this.setTransactionSuccessful();
                };
        });
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

    //try {
    //    hook_native_sqlite();
    //} catch (error) {
    //    devlog(`[HOOK] Failed to install native SQLite hooks: ${error}`);
    //}

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