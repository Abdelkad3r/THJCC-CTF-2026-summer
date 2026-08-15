Man!
====

Forensics / 100 pts / denny


題目敘述
--------

「直升機上的黑盒子損壞了」，只剩下一張最後傳出來的迷因梗圖。
你能幫忙重構現場，找到牢大最後留下的遺言嗎？


檔案
----

final_koby_challenge.png.zip    原始題目附件


附件內容
--------

final_koby_challenge.png        365x547 8-bit RGB PNG（迷因梗圖）
__MACOSX/._final_koby_challenge.png
                                macOS Archive Utility 產生的 AppleDouble
                                資源分支，與題目無關


雜湊值
------

ef6f92513bfd8ee4fc813b8a43556e9249900091e460d41529d8b62ce67ab372  final_koby_challenge.png.zip
3c7dcb3d8734049fa2dbf7a522fb690b981f0fef1038870b076e1298a5009ec1  final_koby_challenge.png


備註
----

PNG 本身完好，八個 chunk 的 CRC 全部通過驗證。
「黑盒子損壞」是題目的誤導敘述。

真正的酬載分成兩層，彼此獨立：

  1. IEND 之後附加了一個 229 bytes 的 ZIP，內含加密的 flag.txt
  2. 該 ZIP 的密碼藏在紅色通道的最低有效位元

解題步驟請見上層目錄的 README.md。
