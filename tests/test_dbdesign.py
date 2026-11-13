"""Database design audit: parsers for SQL/Prisma/Django/Rails/Laravel/SQLAlchemy/TypeORM + live SQLite, design checks, no false positives on a clean schema."""
import os, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import dbdesign as D


def rules(schema, **kw): return [f["rule"] for f in D.analyze(schema, **kw)]


class Parsers(unittest.TestCase):
    def test_prisma_relation_and_index(self):
        s = {}; D.parse_prisma("model User {\n id Int @id\n email String @unique\n posts Post[]\n}\nmodel Post {\n id Int @id\n authorId Int\n author User @relation(fields: [authorId], references: [id], onDelete: Cascade)\n @@index([authorId])\n}\n", "schema.prisma", s)
        self.assertEqual(s["post"]["fks"][0]["ref"], "user"); self.assertTrue(s["post"]["fks"][0]["ondelete"])
        self.assertNotIn("SQL-FK-NO-INDEX", rules(s))

    def test_django_fk_and_unique(self):
        s = {}; D.parse_django("from django.db import models\nclass Customer(models.Model):\n    email = models.EmailField(unique=True)\nclass Order(models.Model):\n    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)\n    total = models.FloatField()\n", "m.py", s)
        r = rules(s); self.assertIn("SQL-MONEY-FLOAT", r); self.assertNotIn("DBD-NOT-UNIQUE", r)

    def test_rails_laravel_sqlalchemy_typeorm(self):
        s = {}
        D.parse_rails('create_table "posts" do |t|\n t.string "title"\n t.references :user, foreign_key: true\n t.timestamps\nend\n', "schema.rb", s)
        D.parse_laravel("Schema::create('tags', function (Blueprint $table) {\n $table->id();\n $table->foreignId('post_id')->constrained()->cascadeOnDelete();\n $table->timestamps();\n });\n", "m.php", s)
        D.parse_sqlalchemy("class Item(Base):\n    __tablename__ = 'items'\n    id = Column(Integer, primary_key=True)\n    owner_id = Column(Integer, ForeignKey('users.id'), index=True)\n", "m.py", s)
        D.parse_typeorm("@Entity('books')\nexport class Book {\n  @PrimaryGeneratedColumn() id: number;\n  @ManyToOne(() => Author) author: Author;\n}\n", "b.ts", s)
        self.assertEqual({"posts", "tags", "items", "books"}, set(s))
        self.assertTrue(s["posts"]["fks"] and s["tags"]["fks"] and s["items"]["fks"] and s["books"]["fks"])


class Checks(unittest.TestCase):
    def sql(self, text):
        s = {}; D.parse_sql(text, "s.sql", s); return s

    def test_design_smells(self):
        r = rules(self.sql("CREATE TABLE accounts (id INT PRIMARY KEY, uuid CHAR(36), balance DOUBLE);\nCREATE TABLE invoices (id INT PRIMARY KEY, account_id INT, amount DECIMAL(12,2));\nCREATE INDEX a ON invoices(account_id);\nCREATE INDEX b ON invoices(account_id, id);\n"))
        for want in ("DBD-MISSING-FK", "DBD-UUID-AS-CHAR", "DBD-REDUNDANT-INDEX", "SQL-MONEY-FLOAT"): self.assertIn(want, r)

    def test_no_relations_and_repeating_group_and_date_string(self):
        t = "".join(f"CREATE TABLE t{i} (id INT PRIMARY KEY, name VARCHAR(10));\n" for i in range(5))
        self.assertIn("DBD-NO-RELATIONS", rules(self.sql(t)))
        self.assertIn("DBD-REPEATING-GROUP", rules(self.sql("CREATE TABLE u (id INT PRIMARY KEY, phone1 TEXT, phone2 TEXT, phone3 TEXT);")))
        self.assertIn("DBD-DATE-AS-STRING", rules(self.sql("CREATE TABLE e (id INT PRIMARY KEY, signup_date VARCHAR(20));")))

    def test_clean_schema_is_quiet(self):
        clean = self.sql("CREATE TABLE users (id BIGINT PRIMARY KEY, email VARCHAR(200) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);\n"
                         "CREATE TABLE posts (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(200) NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);\n"
                         "CREATE INDEX idx_posts_user ON posts(user_id);\n")
        self.assertEqual(rules(clean), [])

    def test_fix_sql_is_text_only_and_commented_when_risky(self):
        fs = D.analyze(self.sql("CREATE TABLE a (id INT PRIMARY KEY);\nCREATE TABLE b (id INT PRIMARY KEY, a_id INT);\n"))
        out = D.fix_sql(fs); self.assertIn("never executed", out); self.assertIn("-- ALTER TABLE b ADD CONSTRAINT", out)


class Live(unittest.TestCase):
    def test_sqlite_introspection(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.db"); c = sqlite3.connect(p)
            c.executescript("CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id));"); c.close()
            fs, summ, sch, msg = D.audit_live(p)
            self.assertEqual(msg, "ok"); self.assertEqual(summ["relations"], 1)
            self.assertIn("SQL-FK-NO-INDEX", rules(sch))   # analyze without 'covered'; audit_live hides it because the legacy sqlite audit already reports it

    def test_mermaid(self):
        s = {}; D.parse_sql("CREATE TABLE a (id INT PRIMARY KEY);\nCREATE TABLE b (id INT PRIMARY KEY, a_id INT REFERENCES a(id));", "s.sql", s)
        m = D.mermaid(s); self.assertTrue(m.startswith("erDiagram")); self.assertIn("a ||--o{ b", m)


class Migrations(unittest.TestCase):
    def test_destructive_migration_needs_review(self):
        f = D.migration_checks("def up():\n    op.drop_table('x')\n", "alembic/versions/001.py")
        self.assertEqual(f[0]["rule"], "DBD-MIG-DROP"); self.assertEqual(f[0]["status"], "needs_validation")
        self.assertEqual(D.migration_checks("drop table x", "src/app.sql"), [])


if __name__ == "__main__":
    unittest.main()
