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

window.SPACECLIENT_DOWNLOAD_URL = 'https://github.com/SpaceClientBeta/cli/releases/download/untagged-9fa95802842375c58377/spaceclient_setup.exe';

// Имя, под которым файл сохранится у пользователя.
window.SPACECLIENT_DOWNLOAD_FILENAME = 'spaceclient_setup.exe';
