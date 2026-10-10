-- schema v4: machine ごとの、認証のレート制限(第二段)の上限。
--
-- NULL は「既定値を使う」を表す(既定値はバイナリの定数であり、ここには
-- 書かない。既定値を変えたときに、未設定の machine がそれに追随する)。
--
-- **範囲(既定値以上、第一段の上限以下)は、アプリケーションが検査する。**
-- ここに数値で書くと、定数を変えるたびに表の作り直しが要る。読む側も
-- 範囲の外の値を範囲に収めてから使う(DESIGN §7.4)。
ALTER TABLE machines ADD COLUMN auth_rate_per_minute INTEGER
    CHECK (auth_rate_per_minute IS NULL OR auth_rate_per_minute > 0);
