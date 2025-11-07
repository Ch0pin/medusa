# Mango Database Migrations

This document contains information about database schema changes and migration instructions for Mango databases.

## Migration from Pre-Framework Detection (Commit: d3349c0)

**Issue**: [#88](https://github.com/Ch0pin/medusa/issues/88)

**Affected Commit**: [d3349c0e01e7e82c885bf8c9b87a8bb9519c93bb](https://github.com/Ch0pin/medusa/commit/d3349c0e01e7e82c885bf8c9b87a8bb9519c93bb)

**Problem**: The commit introduced a new `framework` column to the `Application` table, rendering existing Mango databases incompatible.

### Migration Instructions

If you have an existing Mango database created before commit d3349c0, you need to update your database schema by running the following SQL commands:

```sql
ALTER TABLE "main"."Application" ADD COLUMN framework TEXT;

UPDATE "main"."Application" SET "framework"="None Detected";
```

### How to Apply the Migration

#### Option 1: Using SQLite Command Line

1. Locate your Mango database file (usually `mango.db` in your medusa directory)
2. Open the database with SQLite3:
   ```bash
   sqlite3 mango.db
   ```
3. Run the migration commands:
   ```sql
   ALTER TABLE "main"."Application" ADD COLUMN framework TEXT;
   UPDATE "main"."Application" SET "framework"="None Detected";
   ```
4. Exit SQLite3:
   ```
   .exit
   ```

#### Option 2: Using a Database Browser

1. Open your Mango database file with a SQLite database browser (like DB Browser for SQLite)
2. Go to the "Execute SQL" tab
3. Paste and execute the migration commands above
4. Save the changes

### Verification

After applying the migration, you can verify it worked by checking the table structure:

```sql
.schema Application
```

You should see the `framework` column in the table definition.

### What This Migration Does

- **Adds the `framework` column**: This column stores information about the framework used by the analyzed application
- **Sets default values**: All existing applications will have their framework set to "None Detected"
- **Maintains compatibility**: Your existing analysis data will remain intact

### Troubleshooting

If you encounter any issues during migration:

1. **Backup your database first**: Always create a backup of your `mango.db` file before running migrations
2. **Check file permissions**: Ensure you have write access to the database file
3. **Verify SQLite installation**: Make sure you have SQLite3 installed and accessible

### Future Migrations

This document will be updated with new migration instructions as the database schema evolves. Always check this file when updating Medusa to ensure database compatibility.
