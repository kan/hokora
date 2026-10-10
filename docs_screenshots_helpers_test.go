package main

import (
	"bytes"
	"html"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// docs_screenshots_test.go の補助関数のテスト。
//
// TestDocsScreenshots は、画像を撮る経路(cropScreenshot)を環境変数を渡された
// ときしか通らない。**切り落としを誤ると、下が切れた画像や、余白だらけの
// 画像がマニュアルに載る**ので、合成した PNG で直接確かめる。

var (
	cropBackground = color.NRGBA{R: 0xf7, G: 0xf7, B: 0xf5, A: 0xff}
	cropInk        = color.NRGBA{R: 0x20, G: 0x30, B: 0x40, A: 0xff}
)

// cropTestImage は、背景色で塗った width x height の画像を返す。
func cropTestImage(width, height int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.SetNRGBA(x, y, cropBackground)
		}
	}
	return img
}

// cropFillRows は、[from, to) の行を、位置ごとに違う色で塗る。
//
// 一様な色にしないのは、出力が「入力の上の部分」であることを画素で確かめる
// ためである(行や列がずれた出力を、大きさだけ見て通さない)。
func cropFillRows(img *image.NRGBA, from, to int) {
	for y := from; y < to; y++ {
		for x := img.Rect.Min.X; x < img.Rect.Max.X; x++ {
			//nolint:gosec // G115: テスト用の小さな画像で、256 で割った余りである
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x % 256), G: uint8(y % 256), B: 0x80, A: 0xff})
		}
	}
}

// writeCropPNG は、画像を PNG として書き出す。
func writeCropPNG(t *testing.T, path string, img image.Image) {
	t.Helper()

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// readCropPNG は、PNG を読む。
func readCropPNG(t *testing.T, path string) image.Image {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // G304: このテストが t.TempDir() に作ったファイルである
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return img
}

// assertCropIsTopOf は、got が src の上から wantHeight 行と同じであることを
// 確かめる。
func assertCropIsTopOf(t *testing.T, got, src image.Image, wantHeight int) {
	t.Helper()

	gb, sb := got.Bounds(), src.Bounds()
	if gb.Dx() != sb.Dx() || gb.Dy() != wantHeight {
		t.Fatalf("output size = %dx%d, want %dx%d", gb.Dx(), gb.Dy(), sb.Dx(), wantHeight)
	}
	for y := range wantHeight {
		for x := range sb.Dx() {
			gr, gg, gbl, ga := got.At(gb.Min.X+x, gb.Min.Y+y).RGBA()
			sr, sg, sbl, sa := src.At(sb.Min.X+x, sb.Min.Y+y).RGBA()
			if gr != sr || gg != sg || gbl != sbl || ga != sa {
				t.Fatalf("pixel (%d,%d) differs from the input: the output is not the top part of it", x, y)
			}
		}
	}
}

// **内容の下端 + 余白までを残す。高さの指定は、それより短くするだけである。**
func TestCropScreenshotKeepsTheTopPart(t *testing.T) {
	t.Parallel()

	const (
		width  = 16
		height = 200
	)
	tests := []struct {
		name string
		// draw は背景だけの画像に内容を描く。
		draw       func(img *image.NRGBA)
		height     int // cropScreenshot に渡す高さ
		wantHeight int
	}{
		{
			name:       "内容が途中で終わる: 内容の下端 + 余白",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			wantHeight: 100 + screenshotMargin,
		},
		{
			name:       "内容が上端から始まらない: 上は切らない",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 40, 60) },
			wantHeight: 60 + screenshotMargin,
		},
		{
			// 行を左から見ていって、右端の 1 画素を見落とさないこと。
			name:       "最後の行の内容が右端の 1 画素だけ",
			draw:       func(img *image.NRGBA) { img.SetNRGBA(width-1, 99, cropInk) },
			wantHeight: 100 + screenshotMargin,
		},
		{
			name: "内容の間に背景だけの行がある: 下から見て最初の内容まで",
			draw: func(img *image.NRGBA) {
				cropFillRows(img, 0, 30)
				cropFillRows(img, 90, 100)
			},
			wantHeight: 100 + screenshotMargin,
		},
		{
			name:       "高さの指定が内容より短い: 指定で切る",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			height:     50,
			wantHeight: 50,
		},
		{
			name:       "高さの指定が内容 + 余白と同じ",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			height:     100 + screenshotMargin,
			wantHeight: 100 + screenshotMargin,
		},
		{
			name:       "高さの指定が内容より長い: 伸ばさない",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			height:     180,
			wantHeight: 100 + screenshotMargin,
		},
		{
			name:       "高さの指定が画像より長い: 伸ばさない",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			height:     height * 10,
			wantHeight: 100 + screenshotMargin,
		},
		{
			name:       "高さの指定が負: 指定なしと同じ",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, 100) },
			height:     -1,
			wantHeight: 100 + screenshotMargin,
		},
		{
			// 境界値。下に残る背景がちょうど余白の分なら、画像の全体を残す。
			name:       "下に残る背景がちょうど余白の分",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, height-screenshotMargin) },
			wantHeight: height,
		},
		{
			name:       "背景だけの画像: 余白の分だけ残る",
			draw:       func(*image.NRGBA) {},
			wantHeight: screenshotMargin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			src, dst := filepath.Join(dir, "raw.png"), filepath.Join(dir, "out.png")
			img := cropTestImage(width, height)
			tt.draw(img)
			writeCropPNG(t, src, img)

			if err := cropScreenshot(src, dst, tt.height); err != nil {
				t.Fatalf("cropScreenshot: %v", err)
			}
			assertCropIsTopOf(t, readCropPNG(t, dst), img, tt.wantHeight)
		})
	}
}

// **内容が窓の下端に届いていたら、エラーにして、何も書き出さない。**
//
// 下が切れた画像を黙って書き出すと、マニュアルに載ってから気付く。
// 出力先に前回の画像があるときは、それを壊さないことも見る
// (撮り直しの失敗で、置いてある画像を半端なものに差し替えない)。
func TestCropScreenshotRejectsAPageThatDoesNotFit(t *testing.T) {
	t.Parallel()

	const (
		width  = 16
		height = 200
	)
	tests := []struct {
		name   string
		draw   func(img *image.NRGBA)
		width  int
		height int
		// cropHeight は cropScreenshot に渡す高さである。
		cropHeight int
	}{
		{
			name:   "下に残る背景が余白より 1 行少ない",
			draw:   func(img *image.NRGBA) { cropFillRows(img, 0, height-screenshotMargin+1) },
			width:  width,
			height: height,
		},
		{
			name:   "内容が下から 2 行目まである",
			draw:   func(img *image.NRGBA) { cropFillRows(img, 0, height-1) },
			width:  width,
			height: height,
		},
		{
			// 高さを指定していても、下が切れていることは見逃さない
			// (指定は「上だけ見せる」ためのもので、検査を外すためのものではない)。
			name:       "高さを指定していても、届いていればエラー",
			draw:       func(img *image.NRGBA) { cropFillRows(img, 0, height-1) },
			width:      width,
			height:     height,
			cropHeight: 50,
		},
		{
			name:   "背景だけでも、画像が余白より低い",
			draw:   func(*image.NRGBA) {},
			width:  width,
			height: screenshotMargin - 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			src := filepath.Join(dir, "raw.png")
			img := cropTestImage(tt.width, tt.height)
			tt.draw(img)
			writeCropPNG(t, src, img)

			// 出力先が無いとき。
			missing := filepath.Join(dir, "missing.png")
			err := cropScreenshot(src, missing, tt.cropHeight)
			if err == nil {
				t.Fatal("cropScreenshot succeeded for a page that reaches the bottom")
			}
			if !strings.Contains(err.Error(), "screenshotMaxHeight") {
				t.Errorf("error = %q, want it to tell what to raise", err)
			}
			if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
				t.Errorf("the output was written despite the error (stat: %v)", statErr)
			}

			// 出力先に前回の画像があるとき。
			const previous = "previous image"
			existing := filepath.Join(dir, "existing.png")
			if err := os.WriteFile(existing, []byte(previous), 0o600); err != nil {
				t.Fatalf("write %s: %v", existing, err)
			}
			if err := cropScreenshot(src, existing, tt.cropHeight); err == nil {
				t.Fatal("cropScreenshot succeeded for a page that reaches the bottom")
			}
			got, err := os.ReadFile(existing) //nolint:gosec // G304: このテストが t.TempDir() に作ったファイルである
			if err != nil {
				t.Fatalf("read %s: %v", existing, err)
			}
			if string(got) != previous {
				t.Error("the previous output was overwritten despite the error")
			}
		})
	}
}

// **現状の挙動の固定(検出できない場合がある)。**
//
// cropScreenshot は「左下の画素の色 = 背景色」と決めている。そのため、
// **下端の行が一様な色で、その色の行が余白の分以上続いていれば、それが内容
// (下端まで届いた帯や、行の途中で切れたページの行間)でも背景として切り落とし、
// エラーにしない。** 「届いていたらエラー」は、下端の行に 2 色以上があるか、
// 一様な行が余白より少ないときにしか働かない。
//
// 今のマニュアルの画面は screenshotMaxHeight よりずっと短いので実害は無いが、
// 「下が切れた画像を黙って書き出さない」という保証を、この関数だけで
// 成り立つものとして書かないこと。挙動を変えたら、このテストも直す。
func TestCropScreenshotTreatsAUniformBottomAsBackground(t *testing.T) {
	t.Parallel()

	const (
		width  = 16
		height = 200
		band   = 150 // この行から下端まで、内容である一様な帯が続く
	)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "raw.png"), filepath.Join(dir, "out.png")
	img := cropTestImage(width, height)
	cropFillRows(img, 0, 100)
	for y := band; y < height; y++ {
		for x := range width {
			img.SetNRGBA(x, y, cropInk)
		}
	}
	writeCropPNG(t, src, img)

	// 期待したい挙動はエラーだが、現状は帯を背景とみなして成功する。
	if err := cropScreenshot(src, dst, 0); err != nil {
		t.Fatalf("cropScreenshot: %v (the behaviour changed: update this test and the comment)", err)
	}
	// 帯より上の最後の行(ページの本当の背景色)までが内容になり、帯は
	// 余白の分しか残らない。
	assertCropIsTopOf(t, readCropPNG(t, dst), img, band+screenshotMargin)
}

// 入力が読めないときはエラーにして、何も書き出さない。
func TestCropScreenshotRejectsUnreadableInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// content が nil なら、入力のファイルを作らない。
		content []byte
	}{
		{name: "PNG ではない", content: []byte("<!doctype html><title>not a png</title>")},
		{name: "空のファイル", content: []byte{}},
		{name: "PNG の署名だけ", content: []byte("\x89PNG\r\n\x1a\n")},
		{name: "ファイルが無い"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			src, dst := filepath.Join(dir, "raw.png"), filepath.Join(dir, "out.png")
			if tt.content != nil {
				if err := os.WriteFile(src, tt.content, 0o600); err != nil {
					t.Fatalf("write %s: %v", src, err)
				}
			}

			if err := cropScreenshot(src, dst, 0); err == nil {
				t.Fatal("cropScreenshot succeeded for an unreadable input")
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Errorf("the output was written despite the error (stat: %v)", err)
			}
		})
	}
}

// **色の型が違う PNG でも切れる。**
//
// Chromium が書き出す PNG の色の型(RGB / RGBA / パレット)は決まっていない。
// cropScreenshot は SubImage を持つ型にしか対応しないので、標準ライブラリが
// 返しうる型で通ることを見る。
func TestCropScreenshotHandlesOtherColorModels(t *testing.T) {
	t.Parallel()

	const (
		width  = 16
		height = 120
	)
	bounds := image.Rect(0, 0, width, height)
	tests := []struct {
		name string
		make func() image.Image
	}{
		{
			name: "RGBA(不透明なら PNG は RGB で書かれる)",
			make: func() image.Image {
				img := image.NewRGBA(bounds)
				for y := range height {
					for x := range width {
						c := color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
						if y < 50 {
							//nolint:gosec // G115: テスト用の小さな画像の座標である
							c = color.RGBA{R: uint8(x), G: uint8(y), B: 0x10, A: 0xff}
						}
						img.SetRGBA(x, y, c)
					}
				}
				return img
			},
		},
		{
			name: "パレット",
			make: func() image.Image {
				img := image.NewPaletted(bounds, color.Palette{cropBackground, cropInk, color.NRGBA{R: 0xc0, A: 0xff}})
				for y := range 50 {
					for x := range width {
						//nolint:gosec // G115: 0 か 1 を足すだけである
						img.SetColorIndex(x, y, uint8(1+(x+y)%2))
					}
				}
				return img
			},
		},
		{
			name: "グレースケール",
			make: func() image.Image {
				img := image.NewGray(bounds)
				for y := range height {
					for x := range width {
						c := color.Gray{Y: 0xf0}
						if y < 50 {
							//nolint:gosec // G115: テスト用の小さな画像の座標である
							c = color.Gray{Y: uint8(x + y)}
						}
						img.SetGray(x, y, c)
					}
				}
				return img
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			src, dst := filepath.Join(dir, "raw.png"), filepath.Join(dir, "out.png")
			img := tt.make()
			writeCropPNG(t, src, img)

			if err := cropScreenshot(src, dst, 0); err != nil {
				t.Fatalf("cropScreenshot: %v", err)
			}
			assertCropIsTopOf(t, readCropPNG(t, dst), img, 50+screenshotMargin)
		})
	}
}

// renderCredentialTemplate は、templates/base.html の "credential" を描く。
func renderCredentialTemplate(t *testing.T, cred *machineCredential) string {
	t.Helper()

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	// "credential" は base.html にあり、どのページのテンプレートにも入っている。
	page, ok := tmpl["environment.html"]
	if !ok {
		t.Fatal("environment.html was not parsed")
	}
	var buf bytes.Buffer
	if err := page.ExecuteTemplate(&buf, "credential", cred); err != nil {
		t.Fatalf("execute the credential template: %v", err)
	}
	return buf.String()
}

// **credentialCodeRE は、本物のテンプレートの出力から 2 つの値を取り出す。**
//
// 正規表現はテンプレートの文面(`<dt>` と `<dd>` の間に空白が無いこと、
// `<code>` の属性)に合わせて書かれている。写しではなく、テンプレートを
// 描いた結果に当てる(テンプレートを変えたら、ここで落ちる)。
func TestCredentialCodeREMatchesTheTemplate(t *testing.T) {
	t.Parallel()

	const clientID = "abcdefghij234567klmn"
	// 架空の値。base64url の文字種(英大文字、英小文字、数字、`-`、`_`)を全て含む。
	secret := strings.Repeat("AZaz09-_", 5) + "123"
	body := renderCredentialTemplate(t, &machineCredential{ClientID: clientID, ClientSecret: secret})

	matches := credentialCodeRE.FindAllStringSubmatch(body, -1)
	if len(matches) != 2 {
		t.Fatalf("credentialCodeRE matched %d times, want 2 (body %q)", len(matches), body)
	}
	got := map[string]string{}
	for _, m := range matches {
		got[m[1]] = m[2]
	}
	if got["HOKORA_CLIENT_ID"] != clientID {
		t.Errorf("HOKORA_CLIENT_ID = %q, want %q", got["HOKORA_CLIENT_ID"], clientID)
	}
	if got["HOKORA_CLIENT_SECRET"] != secret {
		t.Errorf("HOKORA_CLIENT_SECRET = %q, want %q", got["HOKORA_CLIENT_SECRET"], secret)
	}

	// 成功する経路は、credentialFromPage そのものも通す(失敗の経路は
	// t.Fatal なので、ここでは呼べない)。
	gotID, gotSecret := credentialFromPage(t, body)
	if gotID != clientID || gotSecret != secret {
		t.Errorf("credentialFromPage = (%q, %q), want (%q, %q)", gotID, gotSecret, clientID, secret)
	}
}

// **取り出せるのは、HTML としてエスケープされた後の文字列である。**
//
// credentialFromPage はエスケープを戻さない。html/template がエスケープする
// 文字(`+` `&` `<` `"` など)が値に入っていると、取り出した値は元の値と
// 食い違い、その値での認証は通らない。**今これが問題にならないのは、
// サーバーが生成する値の文字種(下の TestGeneratedCredentialsSurviveThePage)が
// エスケープされないからである。** 生成する値の文字種を変えたら、
// credentialFromPage に html.UnescapeString を足す。
func TestCredentialCodeREReturnsTheEscapedForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "標準の base64 の記号", value: "ab+cd/ef=="},
		{name: "タグの文字", value: `a<b>c`},
		{name: "アンパサンドと引用符", value: `a&b"c'd`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := renderCredentialTemplate(t, &machineCredential{ClientID: "web-01", ClientSecret: tt.value})
			if strings.Contains(body, tt.value) {
				t.Fatalf("the value was rendered verbatim, the case does not exercise escaping: %q", body)
			}

			var got string
			for _, m := range credentialCodeRE.FindAllStringSubmatch(body, -1) {
				if m[1] == "HOKORA_CLIENT_SECRET" {
					got = m[2]
				}
			}
			if got == "" {
				t.Fatalf("HOKORA_CLIENT_SECRET was not extracted (body %q)", body)
			}
			// 値の途中の `<` で切れずに、値の全体が取れていること。
			if unescaped := html.UnescapeString(got); unescaped != tt.value {
				t.Errorf("unescaped value = %q, want %q (extracted %q)", unescaped, tt.value, got)
			}
			// 現状の挙動: 生の値とは一致しない(上のコメント)。
			if got == tt.value {
				t.Errorf("extracted %q verbatim: the comment above is out of date", got)
			}
		})
	}
}

// **サーバーが生成する credential は、画面から取り出した値がそのまま使える。**
//
// 乱数由来の値なので、1 回だけでは文字種を踏み切れない。繰り返して確かめる。
func TestGeneratedCredentialsSurviveThePage(t *testing.T) {
	t.Parallel()

	for range 200 {
		clientID, err := GenerateClientID()
		if err != nil {
			t.Fatalf("GenerateClientID: %v", err)
		}
		secret, _, err := GenerateClientSecret()
		if err != nil {
			t.Fatalf("GenerateClientSecret: %v", err)
		}

		body := renderCredentialTemplate(t, &machineCredential{ClientID: clientID, ClientSecret: secret})
		gotID, gotSecret := credentialFromPage(t, body)
		if gotID != clientID || gotSecret != secret {
			t.Fatalf("credentialFromPage = (%q, %q), want (%q, %q)", gotID, gotSecret, clientID, secret)
		}
	}
}

// credential の枠が無い画面からは、何も取り出さない。
func TestCredentialCodeREDoesNotMatchOtherMarkup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "空", body: ""},
		{name: "別の名前", body: `<dt>HOKORA_URL</dt><dd><code>https://hokora.example.internal</code></dd>`},
		{name: "値が空", body: `<dt>HOKORA_CLIENT_ID</dt><dd><code></code></dd>`},
		{name: "code の外にある名前", body: `<p>HOKORA_CLIENT_SECRET は一度だけ表示します</p>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if m := credentialCodeRE.FindAllStringSubmatch(tt.body, -1); len(m) != 0 {
				t.Errorf("credentialCodeRE matched %q", m)
			}
		})
	}
}

// screenshotSourcesHash は、呼ぶたびに同じ値を返す。
//
// 記録した値(sources.sha256)と突き合わせるので、辿る順序や map の順序で
// 値が変わると、何も変えていないのに TestDocsScreenshots が落ちる。
func TestScreenshotSourcesHashIsStable(t *testing.T) {
	t.Parallel()

	first := screenshotSourcesHash(t)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("hash = %q, want 64 lowercase hex characters", first)
	}
	for range 5 {
		if got := screenshotSourcesHash(t); got != first {
			t.Fatalf("hash changed between calls: %q, then %q", first, got)
		}
	}
	// 何も読まなかったときの値(空の入力の SHA-256)ではないこと。
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if first == emptySHA256 {
		t.Error("hash is that of an empty input: no embedded file was read")
	}
}

// screenshotRefRE は、docs/assets/screenshots/ の直下の PNG だけを拾う。
func TestScreenshotRefRE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want []string // 取り出される名前。nil なら一致しない
	}{
		{
			name: "マニュアルからの相対参照",
			text: `![ログイン画面](../assets/screenshots/foo-bar_1.png)`,
			want: []string{"foo-bar_1"},
		},
		{
			name: "docs/ の直下からの参照",
			text: `![一覧](assets/screenshots/projects.png)`,
			want: []string{"projects"},
		},
		{
			name: "1 行に 2 つ",
			text: `![a](../assets/screenshots/login.png) ![b](../assets/screenshots/unseal.png)`,
			want: []string{"login", "unseal"},
		},
		{
			name: "HTML の img",
			text: `<img src="../assets/screenshots/audit.png" alt="監査ログ">`,
			want: []string{"audit"},
		},
		{name: "別のディレクトリ", text: `![図](../assets/images/foo.png)`},
		{name: "assets の外の screenshots", text: `![図](../screenshots/foo.png)`},
		{name: "下の階層", text: `![図](../assets/screenshots/old/foo.png)`},
		{name: "別の拡張子", text: `![図](../assets/screenshots/foo.jpg)`},
		{name: "ハッシュのファイル", text: "`docs/assets/screenshots/sources.sha256`"},
		{name: "名前が空", text: `![図](../assets/screenshots/.png)`},
		{name: "ディレクトリだけ", text: "画像は `docs/assets/screenshots/` に置く"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []string
			for _, m := range screenshotRefRE.FindAllStringSubmatch(tt.text, -1) {
				got = append(got, m[1])
			}
			if len(got) != len(tt.want) {
				t.Fatalf("names = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("names = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

// **撮る画面の名前は、screenshotRefRE が拾える文字種であること。**
//
// 拾えない名前(ドットや日本語)の画面を足すと、文書から参照していても
// 「参照されていない」と報告され、原因が名前だと分かりにくい。
func TestDocScreenshotNamesMatchTheReferencePattern(t *testing.T) {
	t.Parallel()

	for _, shot := range renderDocScreenshots(t) {
		ref := "../" + strings.TrimPrefix(screenshotAssets, "docs/") + "/" + shot.name + ".png"
		m := screenshotRefRE.FindStringSubmatch(ref)
		if m == nil || m[1] != shot.name {
			t.Errorf("screenshot name %q is not picked up from %q", shot.name, ref)
		}
	}
}

// **newTestSessionAt のセッションは、渡した時刻を基準に有効である。**
//
// newScreenshotFixture は時計を vaultNow から動かす。vaultNow で作った
// セッションはその時計では期限切れで、全ての画面がログインへの
// リダイレクトになる。
func TestNewTestSessionAtUsesTheGivenTime(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	userID := newTestUser(t, store)
	later := vaultNow.Add(30 * 24 * time.Hour)

	atLater := newTestSessionAt(t, store, userID, later)
	atVaultNow := newTestSession(t, store, userID)

	// later の少し後では、later で作ったほうだけが有効である。
	now := later.Add(time.Minute)
	if _, err := LookupSession(t.Context(), store.DB(), atLater, now); err != nil {
		t.Errorf("LookupSession(session created at the given time): %v", err)
	}
	if _, err := LookupSession(t.Context(), store.DB(), atVaultNow, now); err == nil {
		t.Error("the session created at vaultNow is still valid 30 days later")
	}
	// newTestSession は、従来どおり vaultNow を基準にする。
	if _, err := LookupSession(t.Context(), store.DB(), atVaultNow, vaultNow.Add(time.Minute)); err != nil {
		t.Errorf("LookupSession(session created by newTestSession): %v", err)
	}
}
