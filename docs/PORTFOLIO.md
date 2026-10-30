# Portfolio presentation

## Short English description

LogSentinel is a local mini SIEM for Linux and Windows authentication logs. It normalizes records into SQLite and applies five configurable event-time rules. Each alert includes its matching identity, thresholds, and source evidence. The bundled demo produces 85 events and five explainable alerts without a lab server.

## Technical decisions to show

I used a shared UTC event model so exports with different time representations can be compared. Correlation keys keep different accounts, hosts, and authentication contexts separate.

I used one FastAPI service and SQLite to keep setup small. Event insertion and alert replay share a transaction. A failed import cannot leave half-updated detection results.

The [walkthrough](learning/HOW_IT_WORKS.md), [five scenarios](INDEX.md), and [synthetic case report](reports/SSH_CASE_STUDY.md) connect these choices to actual engine output. The [validation record](VALIDATION.md) states which checks ran.

These statements describe the implementation. They do not assert independent authorship, professional experience, personal learning progress, or production use.

## Kısa Türkçe sunum anlatısı

LogSentinel, Linux ve Windows kimlik doğrulama kayıtlarını inceleyen yerel bir güvenlik analiz projesidir. Amaç, şüpheli giriş örüntülerini kaynak kayıtlarla açıklamaktır.

Uygulama dosyayı okur, olayları ortak şemaya dönüştürür ve SQLite içinde saklar. Beş kural, olay zamanını ve kimlik alanlarını kullanarak uyarı üretir. Kullanıcı her uyarının kanıtlarını arayüzden inceleyebilir.

İlk tasarım kararı, zamanı UTC olarak saklamaktır. Bu karar, farklı saat farklarıyla gelen kayıtları aynı zaman çizelgesinde karşılaştırmayı sağlar.

İkinci karar, korelasyonda makine, kullanıcı ve kaynak bağlamını birlikte kullanmaktır. Bu karar, ilgisiz girişlerin aynı saldırı dizisine katılmasını azaltır. Ancak parola püskürtme ve dağıtılmış denemeler farklı gruplarda kalabilir.

Sentetik demo, gerçek motorla 85 olaydan beş uyarı üretir. Proje dosya tabanlıdır; canlı ajan veya kurumsal ölçek iddiası içermez. Başarılı giriş, hesap ele geçirilmesi kanıtı değildir.

## Suggested demonstration sequence

1. Show the dashboard and the five actual demo alerts.
2. Open the SSH success-after-failures alert and its five records.
3. Explain why the success threshold is three but the failure-only threshold is five.
4. Open the case study and separate observations from hypotheses.
5. Show the tested Windows source-validation rule and its compatibility limit.

Use only synthetic screenshots and samples. The local app has no authentication; do not expose it publicly as a portfolio service. Publish reviewed source and screenshots through your own normal publishing process.

## Demonstrate v1.2 without inventing a learning story

1. Open an alert and show its actual raw records.
2. Replay that evidence in Detection Lab and change one parameter.
3. Compare the 299-second and 300-second boundary experiment.
4. Explain why the cross-account scenario produces no alerts.
5. Save an observation, hypothesis and next evidence request in Case Notes.

These behaviors demonstrate parsing, event-time correlation, rule testing, evidence handling, transaction design and analyst reasoning. They do not establish course completion, independent authorship, professional SOC experience, or production detection accuracy.
