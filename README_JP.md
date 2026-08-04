# esp32-c3-adblock

[English README](README.md)

**Pi-hole風のDNS広告ブロッカー**です。約2ドルのESP32-C3で動作し、*PSRAMは不要*です。
このフォークでは、ESP32 DevKit V1 / WROOM-32向けのビルド環境も追加しています。

要点は、ブロックリスト全体をRAMに置く必要はないことです。ドメインを**ソート済みの40ビットハッシュ**としてフラッシュに保存し、二分探索で照合します。140,000件を超えるドメインを約0.7 MBのフラッシュに収め、約50 KBのRAMだけで照合できます。

```
DNSクエリ受信 ──▶ ドメインを抽出 ──▶ FNV-1aハッシュを計算（親サフィックスも対象）
                                  ──▶ フラッシュ内のハッシュ表を二分探索
                                       ├─ 一致 ──▶ 0.0.0.0 を応答（シンクホール）
                                       └─ 不一致 ──▶ 上流DNSへ転送し、応答を中継
```

## この方式の特徴

一般的なESP32用DNSシンクホールは、ブロックリストをドメインの*文字列*としてRAMへ読み込むため、PSRAMが必要になります。このプロジェクトでは、代わりに固定長の**5バイト（40ビット）ハッシュ**をフラッシュに保存します。

| | 文字列をRAMに保持する方式 | 本プロジェクト（ハッシュをフラッシュに保持） |
|---|---|---|
| ハードウェア | ESP32 + PSRAM（約8ドル） | ESP32-C3、PSRAM不要（約2ドル） |
| 141,000ドメイン | 約2.5 MBのRAM | **0.67 MBのフラッシュ** |
| RAM使用量 | ほぼ全量 | **約50 KB** |
| 照合 | 文字列比較 | 約18回のフラッシュ読み出し（Wi-Fi往復時間を含め約10 ms） |
| ハッシュ衝突 | 該当なし | 141,000件で0件、537,000件で1件 |

**なぜ40ビットなのか。** このフラッシュ容量では40ビットが最適なバランスです。衝突数は誕生日問題に従い、141,000件ではおよそ0件、537,000件ではおよそ1件です。この場合、運悪く別の1ドメインもブロックされます。32ビットにするとフラッシュ使用量を20%削減できますが、250,000件で約7件の衝突が発生します。一方、64ビットでは不要な問題を解決するために、1件あたり3バイト余計に使います。

この手法は、より大きなチップでも利用できます。16 MBフラッシュのESP32-S3なら、ハッシュは約270万ドメインを保存できます。これは8 MB PSRAMへ文字列で保存する場合の約46万6,000件を上回ります。ハッシュをフラッシュに置く方式は、PSRAM上に文字列を置く方式より効率的です。

## ハードウェア

- PSRAMなしで4 MBフラッシュを持つ任意の**ESP32-C3**ボード（C3 SuperMiniで動作確認済み）
- このフォークでは、4 MBフラッシュの**ESP32 DevKit V1 / WROOM-32**も`esp32dev`環境でビルドできます。
- 安定したUSB電源を使用してください。スマートフォン用充電器やルーターのUSBポートが使えます。安価または緩いUSB-C→USB-A変換アダプターでは、Wi-Fi送信時に電圧低下が発生することがあります。
- USB-A→USB-C変換アダプターを使えば、多くのルーター背面にある空きUSBポートへC3ボードを直接接続できます。追加の電源やケースは不要です。

### ケース

C3 SuperMini用の3Dプリントケースは[`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)です。

プリント時の注意点:

- サポートは不要です。積層高0.2 mm、インフィル約15%で十分です。
- **アンテナ側を塞がないでください。** C3のPCBアンテナはUSB-Cポートと反対側の短辺にあるジグザグのパターンです。固い樹脂で覆ったり、近くに金属を置いたりすると、受信信号強度が低下します。
- 通気口を塞がないでください。ボードはアイドル時でも約45～55℃になります。

## ビルドと書き込み（PlatformIO）

初回のみUSBで書き込めば、その後は**ファームウェアとブロックリストの両方をWi-Fi経由で更新**できます。

```bash
# 1. Wi-Fi認証情報を設定します。
#    secrets.hは.gitignoreで除外されるため、ローカルにのみ保存されます。
cp src/secrets.example.h src/secrets.h
#    src/secrets.hのWIFI_SSIDとWIFI_PASSを編集します。

# 2. ブロックリストのハッシュ表を作成します。
#    初期設定はStevenBlack base + Hagezi Lightで、約14万ドメインです。
#    WhatsAppおよびSNSへの影響を避ける構成です。
python3 tools/build_blocklist.py data/blocklist.bin

# 3. ファームウェアとブロックリスト用ファイルシステムを書き込みます。
pio run -t upload
pio run -t uploadfs

# 4. 起動ログからIPアドレスを確認し、ダッシュボードを開きます。
pio device monitor          # -> http://c3adblock.local
```

`platformio.ini`の標準環境はESP32 DevKit V1向けの`esp32dev`です。ESP32-C3を使う場合は、各コマンドへ`-e c3`を追加してください。

```bash
pio run -e c3 -t upload
pio run -e c3 -t uploadfs
pio device monitor -e c3
```

## OTA更新（USB不要）

`http://c3adblock.local` のダッシュボードから操作できます。

- **ブロックリスト**: 新しく作成した`blocklist.bin`を*Blocklist → Upload*からアップロードできます。または、*Remote auto-update*にURLを設定すると、デバイスが定期的に作成済みの`blocklist.bin`を取得します。たとえばGitHubリリースのアセットを指定すれば、一度更新するだけで全デバイスが取得できます。
- **ファームウェア**: *Firmware → OTA update*から`.pio/build/<environment>/firmware.bin`をアップロードできます。デバイスは内容を検証してから、新しいイメージで再起動します。CLIからWi-Fi経由で書き込むこともできます。

  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```

**4 MBフラッシュでのトレードオフ:** ファームウェアOTAにはアプリ用領域が2つ必要です。そのため、ブロックリストに使えるのは約1.3 MB、最大約25万ドメインです。53万7,000件の強力な"ultimate"リストは、ファームウェアOTAを使わない単一アプリ用パーティションでのみ利用できます。用途に応じて`partitions.csv`を選んでください。

## 使い方

端末のDNSサーバーをデバイスのIPアドレスに設定するか、メインDNSの後ろに**セカンダリDNSリゾルバー**として追加します。以下で確認できます。

```bash
dig @<デバイスのIPアドレス> doubleclick.net   # -> 0.0.0.0（ブロック済み）
dig @<デバイスのIPアドレス> github.com        # -> 実際のIPアドレス（上流DNSへ転送）
```

## 注意事項

- **ModemManager**（Fedora/Ubuntuの既定）は`/dev/ttyACM0`を確保し、DTR/RTSを切り替えます。これによりC3がリセットされ、シリアル通信を妨げます。次のように対処できます。

  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```

- C3のUSB-Serial-JTAGコンソールでは、ホスト接続前の起動ログが失われる場合があります。`while(!Serial)`が役に立ちます。
- DNSクライアントはEDNSのOPTレコードを追加します。ブロック時の応答には、質問と回答だけを含める必要があります（`ANCOUNT=1`、`NSCOUNT=ARCOUNT=0`）。これを守らないと不正なDNS応答になります。

## 実装済みと今後の拡張

- 実装済み: Webダッシュボード、端末ごとのブロック／許可数表示、端末の遮断、独自ドメインの追加
- 実装済み: mDNS（`c3adblock.local`）による検出
- 実装済み: Wi-Fi経由のファームウェア／ブロックリストOTA更新、定期的なリモートブロックリスト取得
- 未実装: RAM上のBloom filterによる高速な事前フィルター（大半を占める非一致時のフラッシュ読み出しを省略）
- 未実装: DHCPサーバーとして動作し、自身をDNSサーバーとして配布するプラグアンドプレイ機能

## クレジット

ブロックリストにあるドメインへ`0.0.0.0`を応答するというアイデアは、[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker)から着想を得ています。本プロジェクトは、PSRAMなしのチップにおけるハッシュをフラッシュに保存する最適化に焦点を当てた、独立したゼロからの実装です。

## ライセンス

MIT。詳細は[LICENSE](LICENSE)を参照してください。
