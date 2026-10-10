-- schema v2: 監査ログの batch と、環境での絞り込み用インデックス(#22)
--
-- bulk fetch は key ごとに 1 行を記録する(AGENTS.md ルール 23)。記録の粒度は
-- そのままにして、**同じ呼び出しで書かれた行を画面でまとめられるように**
-- batch_id を持たせる。
--
--   batch_id IS NULL      単独の行、または batch の先頭行(一覧に出るのはこの行)
--   batch_id = 先頭の id   同じ batch の 2 行目以降
--
-- 先頭行を NULL のままにするのは、一覧が `batch_id IS NULL` だけでグループ
-- 単位に並べられ、書き込み側が「先頭行の id を、後続の行に書く」だけで済む
-- ためである。先頭行が batch かどうかは、自分の id を batch_id に持つ行が
-- あるかで分かる。
--
-- **既存の行は埋め戻さない。** v1 には「同じ呼び出し」を表す列が無く、同じ秒・
-- 同じ machine の行をまとめるのは推測になる(同じ秒の 2 回の bulk fetch を
-- 区別できない)。推測を、事実の記録と見分けられない形で監査ログに書かない。
-- 埋め戻せば audit_logs への UPDATE が要るが、**監査ログは追記専用である**
-- (THREAT_MODEL §10.7)。v1 の行は、画面では 1 行ずつ表示される。

ALTER TABLE audit_logs ADD COLUMN batch_id INTEGER;

-- batch の件数と中身を引くためのインデックス。batch に属さない行(大半の
-- 操作)を載せないよう部分インデックスにする。
CREATE INDEX idx_audit_batch ON audit_logs(batch_id) WHERE batch_id IS NOT NULL;

-- 監査ログ画面の「対象の環境」での絞り込み用。環境を持たない行(ログイン、
-- unseal、machine / user の操作など、大半の行)を載せないよう部分インデックスに
-- する。
CREATE INDEX idx_audit_target_env ON audit_logs(target_environment_id, at DESC)
    WHERE target_environment_id IS NOT NULL;
