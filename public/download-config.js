/* ============================================================================
 *  ЕДИНСТВЕННОЕ МЕСТО, ГДЕ МЕНЯЕТСЯ ССЫЛКА НА СКАЧИВАНИЕ EXE
 *  Файл: public/download-config.js  →  переменная ниже.
 *
 *  Требования к ссылке:
 *    • https://
 *    • ПРЯМАЯ — по ней сразу начинается загрузка .exe, без страницы облака.
 *      Ссылка вида https://disk.yandex.ru/d/XXXX или https://cloud.mail.ru/public/XXXX
 *      НЕ подойдёт: браузер откроет страницу облака, а не файл.
 *
 *  Как получить прямую ссылку:
 *    Яндекс.Диск  →  https://getfile.dokpub.com/yandex/get/<публичная ссылка>
 *    GitHub Releases → ссылка с /releases/download/<тег>/spaceclient_setup.exe (самый надёжный)
 *    Cloudflare R2 / S3 → публичный URL объекта
 *
 *  После изменения — задеплой сайт заново и подними ?v= у download-config.js
 *  в public/index.html, иначе у пользователей останется старая ссылка в кеше.
 * ========================================================================== */

window.SPACECLIENT_DOWNLOAD_URL = 'https://downloader.disk.yandex.ru/disk/b631f1e4f210d8b980a58a7217cc6d0c5fbc8d80bf6712a6debd572d676ce314/6aac3962/RlAXz7ZUEH1Ij9kpCbyPA8PfJpmB_hYxJtTyqkHieIIDg6a3q91-9Yss6s6up14xTYcgS3V0T2LszwgOHlMjrg%3D%3D?uid=0&filename=spaceclient_setup.exe&disposition=attachment&hash=UnloLaq589Gln%2BUT8TMLL85vW3J5%2BQb08qyrr%2BDItze0qcDmJpzh1nZIwm%2BtyLgyq/J6bpmRyOJonT3VoXnDag%3D%3D%3A&limit=0&content_type=application%2Fvnd.microsoft.portable-executable&owner_uid=2046000104&fsize=93940387&hid=6d4366ce9f378467d2c6cc82ef5c329f&media_type=executable&tknv=v3&is_direct_zip_experiment=1';

// Имя, под которым файл сохранится у пользователя.
window.SPACECLIENT_DOWNLOAD_FILENAME = 'spaceclient_setup.exe';
