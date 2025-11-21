# PostgreSQL Integration Example

Complete example of using Chatly SDK with PostgreSQL database.

## What You'll Learn

- Implementing custom storage adapters
- PostgreSQL schema design
- Database transactions
- Connection pooling
- Production-ready setup

## Prerequisites

- PostgreSQL installed and running
- Database created: `chatly`

## Setup

```bash
# Install dependencies
npm install

# Create database
createdb chatly

# Run schema migration
psql chatly < schema.sql

# Update database credentials in index.js
# Then run
npm start
```

## Database Schema

See [`schema.sql`](./schema.sql) for the complete schema:
- `users` table
- `messages` table
- `groups` table
- `group_members` table
- Indexes for performance

## Code Structure

```
06-postgresql-integration/
├── README.md
├── package.json
├── schema.sql          # Database schema
├── adapters/
│   ├── userStore.js    # User storage adapter
│   ├── messageStore.js # Message storage adapter
│   └── groupStore.js   # Group storage adapter
└── index.js            # Main example
```

## Output

```
🗄️  Chatly SDK - PostgreSQL Integration
======================================

Connecting to PostgreSQL...
✅ Connected to database: chatly

Creating users in database...
✅ Alice saved to PostgreSQL
✅ Bob saved to PostgreSQL

Sending encrypted messages...
📤 Message 1 saved to database
📤 Message 2 saved to database
📤 Message 3 saved to database

Retrieving messages from database...
📨 Retrieved 3 messages from PostgreSQL
📨 Decrypted: Hello from PostgreSQL!
📨 Decrypted: Messages are persisted
📨 Decrypted: Even after restart!

✅ PostgreSQL integration works!
```

## Production Features

- ✅ Connection pooling
- ✅ Prepared statements (SQL injection protection)
- ✅ Transactions for data integrity
- ✅ Indexes for performance
- ✅ Error handling
- ✅ Graceful shutdown

## Adapting for Other Databases

This pattern works for any SQL database:
- **MySQL**: Change `pg` to `mysql2`
- **SQLite**: Use `better-sqlite3`
- **SQL Server**: Use `mssql`

Just implement the same adapter interfaces!
