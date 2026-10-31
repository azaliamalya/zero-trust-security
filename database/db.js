const path = require('path');
const Database = require('better-sqlite3');
require('dotenv').config({ path: path.resolve(process.cwd(), '.env') });

const dbPath = process.env.DB_PATH || './database/zero_trust.db';
const absolutePath = path.isAbsolute(dbPath) ? dbPath : path.resolve(process.cwd(), dbPath);
const db = new Database(absolutePath);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');
module.exports = db;
