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

    window.addEventListener('pageshow', function (e) {
        if (!e.persisted) return;

        if (mode === 'replace') {
            // 平文を含むページ。
            //
            // 1. **まず DOM を消す。** bfcache は DOM と JS ヒープを含む
            //    スナップショットを復元する。pageshow は復元時に発火するが、
            //    遷移が完了するまでの間に古い平文が表示されうる。
            // 2. **location.replace で安全な GET URL へ退避する。**
            //    reveal ページは POST のレスポンスなので、reload() を使うと
            //    「フォーム再送信の確認」ダイアログが出る。ユーザーが
            //    キャンセルすると、復元された平文がそのまま残り続ける。
            document.documentElement.textContent = '';
            location.replace(body.getAttribute('data-bfcache-url') || '/ui/');
        } else {
            // 通常のページ。全ページ一律で replace にすると、フォーム入力中の
            // ページで「戻る」がダッシュボード行きになり UX を壊す。
            location.reload();
        }
    });
})();
