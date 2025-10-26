'''
## Contact Details of Group 16 Members if Required:
- Tony Le <tony.le@student.adelaide.edu.au>
- Sam Lovat <samuel.lovat@student.adelaide.edu.au>
- Kemal Kiverić <kemal.kiveric@student.adelaide.edu.au>
- Ayii Madut <ayii.madut@student.adelaide.edu.au>
- Rajkarthic <rajkarthick.raju@student.adelaide.edu.au>
'''
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  privkey_store TEXT NOT NULL,
  pake_password TEXT NOT NULL,
  meta TEXT,
  version INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS groups (
  group_id TEXT PRIMARY KEY,
  creator_id TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  meta TEXT,
  version INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  role TEXT DEFAULT 'member',
  wrapped_key TEXT,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, member_id),
  FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);
