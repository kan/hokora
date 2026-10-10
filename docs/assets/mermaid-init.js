// 変換(kramdown + rouge)が出力した mermaid のコードブロックを、図に置き換える。
// mermaid 本体は vendor/ に同梱したものを使い、外部からは読み込まない。
// JavaScript が無効なとき、および描画に失敗したときは、図の原稿がコード
// ブロックのまま残る。
(function () {
    "use strict";

    // rouge は mermaid を知らないので、いまは <pre><code class="language-mermaid"> の
    // 形で出る。rouge が mermaid を扱うようになると <div class="language-mermaid ...">
    // で包んだ形に変わるので、どちらも拾う。
    var blocks = document.querySelectorAll("pre > code.language-mermaid, div.language-mermaid");
    if (blocks.length === 0 || typeof mermaid === "undefined") {
        return;
    }

    var dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: dark ? "dark" : "neutral",
        fontFamily: "inherit",
    });

    blocks.forEach(function (block, i) {
        var source = block.textContent;
        mermaid.render("mermaid-figure-" + i, source).then(function (result) {
            var figure = document.createElement("div");
            figure.className = "mermaid-figure";
            // result.svg の元は、このリポジトリの Markdown に書いた図の原稿だけ
            // である(利用者の入力は通らない)。mermaid も securityLevel: strict で
            // 出力を無害化している。
            figure.innerHTML = result.svg;
            (block.tagName === "CODE" ? block.parentNode : block).replaceWith(figure);
        }).catch(function (err) {
            // 原稿のコードブロックを残す。mermaid が body に足した
            // エラー表示用の要素だけを片付ける。理由はコンソールに出す
            // (GitHub では描けて、同梱の版では描けない図を切り分けるため)。
            console.error("mermaid: figure " + i + " was not rendered", err);
            var leftover = document.getElementById("dmermaid-figure-" + i);
            if (leftover) {
                leftover.remove();
            }
        });
    });
})();
