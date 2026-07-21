// bfcache 対策(DESIGN §9.3)。
//
// Cache-Control: no-store だけでは平文の再表示を防げない。Chrome は 2025 年
// 3〜4 月に、no-store のページも条件を満たせば bfcache に格納する変更を
// 全ユーザーへ展開した。Cookie の変更があると evict されるが、**reveal
// ページは Cookie を変更しないため、この保護は効かない。**
//
// このファイルは「JS は原則不要」の明示的な例外である。CSP の
// script-src 'self' を維持するため、インラインにはしない。
(function () {
    var body = document.body;
    var mode = body.getAttribute('data-bfcache') || 'reload';
    var safeURL = body.getAttribute('data-bfcache-url') || '/ui/';

    // 平文を含むページ(reveal 結果・credential 表示)の「戻る」対策。
    //
    // これらは **POST のレスポンス**である。Chrome は POST で生成された
    // ドキュメントを基本的に bfcache に載せないため、下の pageshow(persisted)
    // は発火しない。その状態で「戻る」を押すと、ブラウザは POST を再要求
    // しようとし、no-store で復元できず「フォーム再送信の確認 / ERR_CACHE_MISS」
    // になる(平文は出ないが、退避もされない)。
    //
    // 読み込み時に履歴エントリの URL を安全な GET(一覧)へ書き換えておくと、
    // bfcache に載らずに戻られた場合でも POST の再送ではなく一覧の GET に
    // なる。replaceState はドキュメントを再読み込みしないので、いま表示中の
    // 平文はそのまま残る。再読み込み(F5)しても一覧へ行くだけで、平文の
    // 再表示(= 新たな監査記録)を招かない。
    if (mode === 'replace') {
        try {
            history.replaceState(null, '', safeURL);
        } catch (e) {
            // replaceState が使えない環境では pageshow 側に委ねる。
        }
    }

    window.addEventListener('pageshow', function (e) {
        if (!e.persisted) return;

        if (mode === 'replace') {
            // 平文を含むページが bfcache から復元された場合の保険。
            //
            // 1. **まず DOM を消す。** bfcache は DOM と JS ヒープを含む
            //    スナップショットを復元する。pageshow は復元時に発火するが、
            //    遷移が完了するまでの間に古い平文が表示されうる。
            // 2. **location.replace で安全な GET URL へ退避する。**
            //    reload() は POST の再送確認を招く。
            document.documentElement.textContent = '';
            location.replace(safeURL);
        } else {
            // 通常のページ。全ページ一律で replace にすると、フォーム入力中の
            // ページで「戻る」がダッシュボード行きになり UX を壊す。
            location.reload();
        }
    });
})();
