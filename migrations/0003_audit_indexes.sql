-- schema v3: 監査ログの索引を、使う問い合わせに合わせて作り直す
--
-- v1 は audit_logs の全行に 4 本の索引を張っており、**索引の合計が表の本体と
-- 同じ大きさ**だった(本番の実測: 表 73MB、索引 73MB)。監査の 1 行を書く
-- たびに 4 本を更新してもいた(secret の読み取りのたびに通る、fail closed の
-- 経路である)。0002 で一覧専用の索引(idx_audit_head / _machine / _env)を
-- 足したので、v1 の索引を「該当する行だけを載せる」形に絞り、置き換えの済んだ
-- ものを外す。

-- 時刻で引く。一覧は idx_audit_head(0002)で引くようになった。
--
-- **DB を直接引く調査で、batch の後続行も含めて時刻で引くときは、先頭行から
-- 辿る。** 後続行の at は先頭行と同じ(同じ呼び出しで書く)なので、
--
--   SELECT * FROM audit_logs
--   WHERE id IN (SELECT id FROM audit_logs WHERE batch_id IS NULL AND at >= ? AND at < ?)
--      OR batch_id IN (SELECT id FROM audit_logs WHERE batch_id IS NULL AND at >= ? AND at < ?)
--
-- で、その期間の全行が索引(idx_audit_head と idx_audit_batch)だけで引ける。
-- v2 より前の行は batch を持たないので、全て先頭行として idx_audit_head に載る。
DROP INDEX idx_audit_at;

-- 実行者が machine の行。一覧は idx_audit_head_machine(0002)で引く。
-- 後続行も含めて引くときは、上と同じく先頭行から辿る(後続行の実行者は先頭行と
-- 同じである)。
DROP INDEX idx_audit_actor_machine;

-- 実行者が user の行は、全体のごく一部である(本番では 65 万行中 30 行)のに、
-- v1 の索引は全行ぶんの大きさを持っていた。該当する行だけを載せ、一覧の並び順
-- (at DESC, id DESC)も持たせる。
DROP INDEX idx_audit_actor_user;
CREATE INDEX idx_audit_actor_user ON audit_logs(actor_user_id, at DESC, id DESC)
    WHERE actor_user_id IS NOT NULL;

-- 実行者が anonymous の行(失敗したログイン、存在しない client_id やレート制限に
-- 当たった認証、admin socket 経由の操作)。v1 では idx_audit_actor_machine の
-- NULL の側で引いていた。該当する行だけを、一覧の並び順どおりに持つ。
--
-- **行が少ないとは限らない。** 認証の失敗は未認証で起こせるので、試行が続けば
-- anonymous の行は増える(増え方はレート制限で頭打ちになる)。この索引は
-- 「anonymous の行だけ」を持つのであって、小さいことを当てにしない。
CREATE INDEX idx_audit_anonymous ON audit_logs(at DESC, id DESC)
    WHERE actor_user_id IS NULL AND actor_machine_id IS NULL;

-- key で引く(「この key を誰が読んだか」)。**コードに使う問い合わせは無いが、
-- 残す。** 画面は key での絞り込みを持たない(DESIGN §5.2)ので、侵害の調査で
-- DB を直接引くときに頼れるのはこれだけになる。key を対象にしない行(認証、
-- ログイン、seal など)は載せない。
DROP INDEX idx_audit_target_item;
CREATE INDEX idx_audit_target_item ON audit_logs(target_item_id, at DESC)
    WHERE target_item_id IS NOT NULL;

-- **DROP INDEX はファイルを小さくしない。** 空いたページは DB の中で再利用
-- される(以後の追記がそこへ入り、その分だけファイルの伸びが止まる)。
-- `hokora backup` の出力は VACUUM INTO で詰め直されるので、こちらはすぐ小さくなる。
