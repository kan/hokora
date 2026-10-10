// ページの横に、見出し(h2 と h3)の一覧を出す。一覧は画面に固定され、
// いま読んでいる見出しに印が付く。見出しの id は変換(kramdown)が付けたものを
// 使う。JavaScript が無効なとき、および見出しが少ないページでは、何も出さない。
(function () {
    "use strict";

    var aside = document.querySelector(".outline");
    var headings = Array.prototype.slice.call(document.querySelectorAll("main h2[id], main h3[id]"));
    if (!aside || headings.length < 2) {
        return;
    }

    var list = aside.querySelector("ul");
    var links = headings.map(function (heading) {
        var link = document.createElement("a");
        link.href = "#" + encodeURIComponent(heading.id);
        link.textContent = heading.textContent;
        var item = document.createElement("li");
        item.className = "outline-" + heading.tagName.toLowerCase();
        item.appendChild(link);
        list.appendChild(item);
        return link;
    });
    aside.hidden = false;

    // 上部のバーの下に来た、いちばん下の見出しを「いま読んでいる所」とする。
    var offset = 5 * parseFloat(getComputedStyle(document.documentElement).fontSize);
    var current = null;
    function mark() {
        var index = -1;
        for (var i = 0; i < headings.length; i++) {
            if (headings[i].getBoundingClientRect().top > offset) {
                break;
            }
            index = i;
        }
        // ページの末尾まで来たら、短い最後の節にも印が届くようにする。
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
            index = headings.length - 1;
        }
        var next = index < 0 ? null : links[index];
        if (next === current) {
            return;
        }
        if (current) {
            current.removeAttribute("aria-current");
        }
        current = next;
        if (current) {
            current.setAttribute("aria-current", "location");
            // 長い一覧では、印の付いた項目を一覧の中に見える位置へ送る。
            // ページではなく一覧だけを動かすので、scrollIntoView は使わない。
            var box = aside.getBoundingClientRect();
            var row = current.getBoundingClientRect();
            if (row.top < box.top || row.bottom > box.bottom) {
                aside.scrollTop += row.top - box.top - box.height / 2;
            }
        }
    }

    var queued = false;
    function schedule() {
        if (queued) {
            return;
        }
        queued = true;
        requestAnimationFrame(function () {
            queued = false;
            mark();
        });
    }
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    mark();
})();
