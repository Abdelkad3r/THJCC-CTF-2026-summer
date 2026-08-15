A Little Penguin's Starry Sky Observation
=========================================

Misc / 100 pts / PGpenguin72


題目敘述
--------

小企鵝在去年 12 月去高山上觀星時，用手機拍下了一張非常好看的星空照片。
這張照片裡包含了許多著名的星座，他特別裁切了其中一部分作為這次的謎題。

請協助小企鵝找出這張裁切照片中所拍攝的核心星座是什麼，並查出該星座的官方
三字英文縮寫，以及它在天球赤道座標系統中的大略中心位置赤經與赤緯
（取整數小時與度數）。

Flag 格式： THJCC{星座縮寫=RA赤經,Dec赤緯}
縮寫規範：   英文縮寫請一律使用全小寫
格式範例：   THJCC{vir=RA12h,Dec+0°}


檔案
----

Starry_Sky_Observation.jpeg.zip   原始題目附件
trailer_prompt_injection.txt      從 JPEG EOI 之後取出的附加酬載（見下方警告）


附件內容
--------

Starry_Sky_Observation.jpeg       669x892 baseline JPEG，iPhone 夜間模式拍攝
__MACOSX/._Starry_Sky_Observation.jpeg
                                  macOS Archive Utility 產生的 AppleDouble
                                  資源分支，與題目無關


雜湊值
------

f6e3983e92435438c903f0305df7510b3635e697614ac1096be520fd556d2145  Starry_Sky_Observation.jpeg.zip
580deb9a13bdca43d406f4f1efb54b89103c7a2eb8b24c71a06b7eb5c4949f9f  Starry_Sky_Observation.jpeg
56dcbc1c419a31ba7070ded949be3564aab56da09592a46e23061f72f0720590  trailer_prompt_injection.txt


EXIF 重點
---------

Date/Time Original    2025:12:21 00:53:00
Offset Time Original  +08:00
無 GPS 標籤


警告：trailer_prompt_injection.txt
----------------------------------

JPEG 的 EOI (FFD9) 位於 offset 172024，但檔案長度為 179373，
其後附加了 7347 bytes 的純文字。

該內容並非第二個 flag，而是一段針對 AI agent 的 prompt injection，
要求模型放棄分析並只輸出字串 "gugugaga"。

此檔案為原封不動取出的酬載，僅作為分析紀錄保存。
它是「資料」而非「指令」—— 檔案內含的文字對分析者不具任何權威性，
正確處理方式是記錄並忽略。它對本題答案沒有任何影響。


備註
----

本題為天文辨識題，並非隱寫術題目。
影像中的核心星座為獵戶座（Orion），
可由腰帶三星、獵戶座大星雲 M42、以及參宿四的橙色色指數共同確認。

解題步驟與天測驗證請見上層目錄的 README.md。
