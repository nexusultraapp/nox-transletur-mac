#include <chiaki/common.h>
#include <chiaki/log.h>
#include <chiaki/regist.h>
#include <chiaki/session.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <windows.h>
#  define NOXIR_EXPORT __declspec(dllexport)
#  define NOXIR_CALL __cdecl
#else
#  define _POSIX_C_SOURCE 200809L
#  include <pthread.h>
#  include <sys/time.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <errno.h>
#  include <stdatomic.h>
#  define NOXIR_EXPORT __attribute__((visibility("default")))
#  define NOXIR_CALL
#endif

#define NOXIR_ERROR_CAPACITY 512
#define NOXIR_REGISTRATION_TIMEOUT_MS 30000

typedef struct noxir_registration_context_t
{
#if defined(_WIN32)
    HANDLE completed;
#else
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int completed;
#endif
    int result;
    ChiakiRegisteredHost host;
    char last_log_message[NOXIR_ERROR_CAPACITY];
} NoxirRegistrationContext;

typedef struct noxir_stream_context_t
{
    ChiakiSession session;
    ChiakiLog log;
#if defined(_WIN32)
    HANDLE pipe;
    volatile LONG stopping;
    volatile LONG failed;
#else
    int socket_fd;
    atomic_int stopping;
    atomic_int failed;
#endif
    char error[NOXIR_ERROR_CAPACITY];
    int initialized;
} NoxirStreamContext;

static NoxirStreamContext stream_context;
#if defined(_WIN32)
static PVOID vectored_exception_handler;
#endif

static void copy_text(char *destination, size_t capacity, const char *source);

#if defined(_WIN32)
static uintptr_t module_for_address(const void *address, char *module, size_t capacity)
{
    copy_text(module, capacity, "unknown");
    MEMORY_BASIC_INFORMATION memory_info;
    if (address && VirtualQuery(address, &memory_info, sizeof(memory_info)) == sizeof(memory_info) && memory_info.AllocationBase)
    {
        GetModuleFileNameA((HMODULE)memory_info.AllocationBase, module, (DWORD)capacity);
        return (uintptr_t)memory_info.AllocationBase;
    }
    return 0;
}

static LONG WINAPI native_exception_filter(EXCEPTION_POINTERS *exception)
{
    if (!exception || !exception->ExceptionRecord ||
        exception->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    char local_app_data[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("LOCALAPPDATA", local_app_data, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
        return EXCEPTION_CONTINUE_SEARCH;

    char folder[MAX_PATH];
    char path[MAX_PATH];
    _snprintf(folder, sizeof(folder), "%s\\NOXIR Play", local_app_data);
    _snprintf(path, sizeof(path), "%s\\native-crash.log", folder);
    CreateDirectoryA(folder, NULL);

    EXCEPTION_RECORD *record = exception->ExceptionRecord;
    char module[MAX_PATH] = "unknown";
    uintptr_t exception_module_base = module_for_address(record->ExceptionAddress, module, sizeof(module));

    char message[2048];
    int count = _snprintf(message, sizeof(message),
        "NOXIR native exception: code=0x%08lX instruction=%p module=%s module_base=%p instruction_rva=0x%llX",
        record->ExceptionCode, record->ExceptionAddress, module, (void *)exception_module_base,
        (unsigned long long)(exception_module_base ? (uintptr_t)record->ExceptionAddress - exception_module_base : 0));
    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record->NumberParameters >= 2)
    {
        const char *operation = record->ExceptionInformation[0] == 0 ? "read" :
            record->ExceptionInformation[0] == 1 ? "write" : "execute";
        if (count > 0 && (size_t)count < sizeof(message))
            _snprintf(message + count, sizeof(message) - (size_t)count,
                " operation=%s target=%p", operation, (void *)record->ExceptionInformation[1]);
    }
#ifdef _WIN64
    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && exception->ContextRecord)
    {
        uintptr_t stack_pointer = (uintptr_t)exception->ContextRecord->Rsp;
        MEMORY_BASIC_INFORMATION stack_info;
        if (VirtualQuery((const void *)stack_pointer, &stack_info, sizeof(stack_info)) == sizeof(stack_info) &&
            stack_info.State == MEM_COMMIT && (uintptr_t)stack_info.BaseAddress <= stack_pointer &&
            stack_pointer + sizeof(uintptr_t) <= (uintptr_t)stack_info.BaseAddress + stack_info.RegionSize)
        {
            uintptr_t return_address = *(const uintptr_t *)stack_pointer;
            char caller_module[MAX_PATH];
            uintptr_t caller_base = module_for_address((const void *)(return_address ? return_address - 1 : 0), caller_module, sizeof(caller_module));
            size_t used = strlen(message);
            if (used < sizeof(message))
                _snprintf(message + used, sizeof(message) - used,
                    " rsp=%p return=%p caller_module=%s caller_base=%p caller_rva=0x%llX", (void *)stack_pointer,
                    (void *)return_address, caller_module, (void *)caller_base,
                    (unsigned long long)(caller_base && return_address ? return_address - 1 - caller_base : 0));
        }
    }
#endif
    strncat(message, "\r\n", sizeof(message) - strlen(message) - 1);

    HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(file, message, (DWORD)strlen(message), &written, NULL);
        FlushFileBuffers(file);
        CloseHandle(file);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif /* _WIN32 */

static void copy_text(char *destination, size_t capacity, const char *source)
{
    if (!destination || capacity == 0)
        return;

    if (!source)
        source = "";

    strncpy(destination, source, capacity - 1);
    destination[capacity - 1] = '\0';
}

static void registration_log(ChiakiLogLevel level, const char *message, void *user)
{
    (void)level;
    NoxirRegistrationContext *context = (NoxirRegistrationContext *)user;
    if (!context)
        return;
    copy_text(context->last_log_message, sizeof(context->last_log_message), message);
}

static void registration_finished(ChiakiRegistEvent *event, void *user)
{
    NoxirRegistrationContext *context = (NoxirRegistrationContext *)user;
    if (!context)
        return;
    if (event->type == CHIAKI_REGIST_EVENT_TYPE_FINISHED_SUCCESS && event->registered_host)
    {
        memcpy(&context->host, event->registered_host, sizeof(context->host));
        context->result = 0;
    }
    else if (event->type == CHIAKI_REGIST_EVENT_TYPE_FINISHED_CANCELED)
    {
        context->result = 2;
    }
    else
    {
        context->result = 1;
    }

#if defined(_WIN32)
    SetEvent(context->completed);
#else
    pthread_mutex_lock(&context->mutex);
    context->completed = 1;
    pthread_cond_broadcast(&context->cond);
    pthread_mutex_unlock(&context->mutex);
#endif
}

#if defined(_WIN32)
/* ---- Windows-only named-pipe streaming helpers ---- */

static void stream_log(ChiakiLogLevel level, const char *message, void *user)
{
    (void)level;
    NoxirStreamContext *context = user ? (NoxirStreamContext *)user : &stream_context;
    copy_text(context->error, sizeof(context->error), message);
}

static void stream_cant_display(void *user, bool cant_display)
{
    NoxirStreamContext *context = user ? (NoxirStreamContext *)user : &stream_context;
    if (cant_display)
    {
        copy_text(context->error, sizeof(context->error), "PS5 bu ekranın akışına izin vermiyor (HDCP veya korumalı içerik).");
        InterlockedExchange(&context->failed, 1);
    }
}

static void stream_event(ChiakiEvent *event, void *user)
{
    NoxirStreamContext *context = user ? (NoxirStreamContext *)user : &stream_context;
    if (event && event->type == CHIAKI_EVENT_QUIT && event->quit.reason != CHIAKI_QUIT_REASON_STOPPED)
    {
        copy_text(context->error, sizeof(context->error), event->quit.reason_str ? event->quit.reason_str : chiaki_quit_reason_string(event->quit.reason));
        InterlockedExchange(&context->failed, 1);
    }
}

static bool stream_video_sample(uint8_t *buf, size_t size, int32_t frames_lost, bool recovered, void *user)
{
    (void)frames_lost;
    (void)recovered;
    NoxirStreamContext *context = (NoxirStreamContext *)user;
    if (InterlockedCompareExchange(&context->stopping, 0, 0) != 0 || size == 0)
        return false;

    if (context->pipe == INVALID_HANDLE_VALUE)
    {
        context->pipe = CreateFileA("\\\\.\\pipe\\noxirplay-remote-h264", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (context->pipe == INVALID_HANDLE_VALUE)
        {
            return true;
        }
    }

    size_t offset = 0;
    while (offset < size)
    {
        if (InterlockedCompareExchange(&context->stopping, 0, 0) != 0)
            return false;

        DWORD written = 0;
        DWORD chunk = (DWORD)((size - offset) > 0x7ffff000 ? 0x7ffff000 : (size - offset));
        if (!WriteFile(context->pipe, buf + offset, chunk, &written, NULL) || written == 0)
        {
            CloseHandle(context->pipe);
            context->pipe = INVALID_HANDLE_VALUE;
            copy_text(context->error, sizeof(context->error), "Video aktarım kanalı kapandı.");
            InterlockedExchange(&context->failed, 1);
            return false;
        }
        offset += written;
    }
    return true;
}

static void dummy_audio_header(ChiakiAudioHeader *header, void *user)
{
    (void)header;
    (void)user;
}

static void dummy_audio_frame(uint8_t *buf, size_t size, void *user)
{
    (void)buf;
    (void)size;
    (void)user;
}
#endif /* _WIN32 */

#if defined(__APPLE__)
static void mac_stream_log(ChiakiLogLevel level, const char *message, void *user)
{
    (void)level;
    NoxirStreamContext *context = user ? user : &stream_context;
    copy_text(context->error, sizeof(context->error), message);
}

static void mac_stream_event(ChiakiEvent *event, void *user)
{
    NoxirStreamContext *context = user ? user : &stream_context;
    if (event && event->type == CHIAKI_EVENT_QUIT && event->quit.reason != CHIAKI_QUIT_REASON_STOPPED)
    {
        copy_text(context->error, sizeof(context->error),
                  event->quit.reason_str ? event->quit.reason_str : chiaki_quit_reason_string(event->quit.reason));
        atomic_store(&context->failed, 1);
    }
}

static void mac_stream_cant_display(void *user, bool cant_display)
{
    NoxirStreamContext *context = user ? user : &stream_context;
    if (cant_display)
    {
        copy_text(context->error, sizeof(context->error), "PS5 bu ekranın akışına izin vermiyor (HDCP veya korumalı içerik).");
        atomic_store(&context->failed, 1);
    }
}

static bool mac_stream_video_sample(uint8_t *buf, size_t size, int32_t frames_lost, bool recovered, void *user)
{
    (void)frames_lost;
    (void)recovered;
    NoxirStreamContext *context = user ? user : &stream_context;
    if (atomic_load(&context->stopping) || size == 0)
        return false;

    size_t offset = 0;
    while (offset < size && !atomic_load(&context->stopping))
    {
        ssize_t written = send(context->socket_fd, buf + offset, size - offset, 0);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
        {
            copy_text(context->error, sizeof(context->error), "Video aktarım soketi kapandı.");
            atomic_store(&context->failed, 1);
            return false;
        }
        offset += (size_t)written;
    }
    return !atomic_load(&context->stopping);
}

static void mac_dummy_audio_header(ChiakiAudioHeader *header, void *user)
{
    (void)header;
    (void)user;
}

static void mac_dummy_audio_frame(uint8_t *buf, size_t size, void *user)
{
    (void)buf;
    (void)size;
    (void)user;
}
#endif

NOXIR_EXPORT int NOXIR_CALL noxir_get_stream_error(char *error_message, size_t error_capacity)
{
#if defined(_WIN32)
    if (InterlockedCompareExchange(&stream_context.failed, 0, 0) == 0)
        return 0;
    copy_text(error_message, error_capacity, stream_context.error);
    return 1;
#elif defined(__APPLE__)
    if (!atomic_load(&stream_context.failed))
        return 0;
    copy_text(error_message, error_capacity, stream_context.error);
    return 1;
#else
    (void)error_message;
    (void)error_capacity;
    return 0;
#endif
}

NOXIR_EXPORT int NOXIR_CALL noxir_start_ps5_stream(
    const char *host, const uint8_t *registration_key, const uint8_t *morning,
    char *error_message, size_t error_capacity, uint16_t stream_port)
{
#if defined(_WIN32)
    (void)stream_port;
    if (!host || !registration_key || !morning)
    {
        copy_text(error_message, error_capacity, "PS5 bağlantı bilgileri eksik.");
        return -20;
    }
    if (stream_context.initialized)
    {
        copy_text(error_message, error_capacity, "PS5 görüntü bağlantısı zaten açık.");
        return -21;
    }
    if (!vectored_exception_handler)
        vectored_exception_handler = AddVectoredExceptionHandler(1, native_exception_filter);

    ChiakiErrorCode init_result = chiaki_lib_init();
    if (init_result != CHIAKI_ERR_SUCCESS)
    {
        copy_text(error_message, error_capacity, chiaki_error_string(init_result));
        return -22;
    }

    memset(&stream_context, 0, sizeof(stream_context));
    stream_context.pipe = INVALID_HANDLE_VALUE;
    chiaki_log_init(&stream_context.log, CHIAKI_LOG_ALL, stream_log, &stream_context);

    ChiakiConnectInfo info;
    memset(&info, 0, sizeof(info));
    info.ps5 = true;
    info.host = host;
    memcpy(info.regist_key, registration_key, sizeof(info.regist_key));
    memcpy(info.morning, morning, sizeof(info.morning));
    chiaki_connect_video_profile_preset(&info.video_profile, CHIAKI_VIDEO_RESOLUTION_PRESET_720p, CHIAKI_VIDEO_FPS_PRESET_60);
    info.video_profile.codec = CHIAKI_CODEC_H264;
    info.video_profile_auto_downgrade = true;
    info.audio_video_disabled = CHIAKI_AUDIO_DISABLED;
    info.enable_idr_on_fec_failure = true;
    info.packet_loss_max = 0.0;

    ChiakiErrorCode result = chiaki_session_init(&stream_context.session, &info, &stream_context.log);
    if (result != CHIAKI_ERR_SUCCESS)
    {
        copy_text(error_message, error_capacity, chiaki_error_string(result));
        return -23;
    }
    chiaki_session_set_event_cb(&stream_context.session, stream_event, &stream_context);
    chiaki_session_set_video_sample_cb(&stream_context.session, stream_video_sample, &stream_context);

    ChiakiAudioSink audio_sink = {0};
    audio_sink.user = &stream_context;
    audio_sink.header_cb = dummy_audio_header;
    audio_sink.frame_cb = dummy_audio_frame;
    stream_context.session.audio_sink = audio_sink;
    stream_context.session.haptics_sink = audio_sink;

    ChiakiCtrlDisplaySink display_sink = {0};
    display_sink.user = &stream_context;
    display_sink.cantdisplay_cb = stream_cant_display;
    chiaki_session_ctrl_set_display_sink(&stream_context.session, &display_sink);
    stream_context.initialized = 1;
    result = chiaki_session_start(&stream_context.session);
    if (result != CHIAKI_ERR_SUCCESS)
    {
        chiaki_session_fini(&stream_context.session);
        stream_context.initialized = 0;
        copy_text(error_message, error_capacity, chiaki_error_string(result));
        return -24;
    }
    copy_text(error_message, error_capacity, "");
    return 0;
#elif defined(__APPLE__)
    if (!host || !registration_key || !morning || stream_port == 0)
    {
        copy_text(error_message, error_capacity, "PS5 bağlantı bilgileri eksik.");
        return -20;
    }
    if (stream_context.initialized)
    {
        copy_text(error_message, error_capacity, "PS5 görüntü bağlantısı zaten açık.");
        return -21;
    }

    memset(&stream_context, 0, sizeof(stream_context));
    atomic_init(&stream_context.stopping, 0);
    atomic_init(&stream_context.failed, 0);
    stream_context.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (stream_context.socket_fd < 0)
    {
        copy_text(error_message, error_capacity, "Yerel video aktarım soketi oluşturulamadı.");
        return -22;
    }
    int no_sigpipe = 1;
    if (setsockopt(stream_context.socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0)
    {
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, "Yerel video aktarım soketi hazırlanamadı.");
        return -22;
    }
    struct timeval send_timeout = {2, 0};
    if (setsockopt(stream_context.socket_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) != 0)
    {
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, "Yerel video aktarım soketi zaman aşımı ayarlanamadı.");
        return -22;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(stream_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(stream_context.socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, "Yerel video aktarım sunucusuna bağlanılamadı.");
        return -22;
    }

    ChiakiErrorCode init_result = chiaki_lib_init();
    if (init_result != CHIAKI_ERR_SUCCESS)
    {
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, chiaki_error_string(init_result));
        return -23;
    }

    chiaki_log_init(&stream_context.log, CHIAKI_LOG_ALL, mac_stream_log, &stream_context);
    ChiakiConnectInfo info;
    memset(&info, 0, sizeof(info));
    info.ps5 = true;
    info.host = host;
    memcpy(info.regist_key, registration_key, sizeof(info.regist_key));
    memcpy(info.morning, morning, sizeof(info.morning));
    chiaki_connect_video_profile_preset(&info.video_profile, CHIAKI_VIDEO_RESOLUTION_PRESET_720p, CHIAKI_VIDEO_FPS_PRESET_60);
    info.video_profile.codec = CHIAKI_CODEC_H264;
    info.video_profile_auto_downgrade = true;
    info.audio_video_disabled = CHIAKI_AUDIO_DISABLED;
    info.enable_idr_on_fec_failure = true;
    info.packet_loss_max = 0.0;

    ChiakiErrorCode result = chiaki_session_init(&stream_context.session, &info, &stream_context.log);
    if (result != CHIAKI_ERR_SUCCESS)
    {
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, chiaki_error_string(result));
        return -24;
    }
    chiaki_session_set_event_cb(&stream_context.session, mac_stream_event, &stream_context);
    chiaki_session_set_video_sample_cb(&stream_context.session, mac_stream_video_sample, &stream_context);

    ChiakiAudioSink audio_sink = {0};
    audio_sink.user = &stream_context;
    audio_sink.header_cb = mac_dummy_audio_header;
    audio_sink.frame_cb = mac_dummy_audio_frame;
    stream_context.session.audio_sink = audio_sink;
    stream_context.session.haptics_sink = audio_sink;

    ChiakiCtrlDisplaySink display_sink = {0};
    display_sink.user = &stream_context;
    display_sink.cantdisplay_cb = mac_stream_cant_display;
    chiaki_session_ctrl_set_display_sink(&stream_context.session, &display_sink);
    stream_context.initialized = 1;
    result = chiaki_session_start(&stream_context.session);
    if (result != CHIAKI_ERR_SUCCESS)
    {
        chiaki_session_fini(&stream_context.session);
        stream_context.initialized = 0;
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
        copy_text(error_message, error_capacity, chiaki_error_string(result));
        return -25;
    }
    copy_text(error_message, error_capacity, "");
    return 0;
#else
    (void)host;
    (void)registration_key;
    (void)morning;
    (void)stream_port;
    copy_text(error_message, error_capacity, "PS5 görüntü aktarımı macOS'ta henüz desteklenmiyor (FFmpeg ekran yakalama kullanın).");
    return -20;
#endif
}

NOXIR_EXPORT void NOXIR_CALL noxir_stop_ps5_stream(void)
{
#if defined(_WIN32)
    if (!stream_context.initialized)
        return;
    InterlockedExchange(&stream_context.stopping, 1);

    if (stream_context.pipe != INVALID_HANDLE_VALUE)
    {
        HANDLE pipe = stream_context.pipe;
        stream_context.pipe = INVALID_HANDLE_VALUE;
        CloseHandle(pipe);
    }

    chiaki_session_stop(&stream_context.session);
    chiaki_session_join(&stream_context.session);
    chiaki_session_fini(&stream_context.session);
    stream_context.initialized = 0;
#elif defined(__APPLE__)
    if (!stream_context.initialized)
        return;
    atomic_store(&stream_context.stopping, 1);
    chiaki_session_stop(&stream_context.session);
    chiaki_session_join(&stream_context.session);
    chiaki_session_fini(&stream_context.session);
    stream_context.initialized = 0;
    if (stream_context.socket_fd >= 0)
    {
        shutdown(stream_context.socket_fd, SHUT_RDWR);
        close(stream_context.socket_fd);
        stream_context.socket_fd = -1;
    }
#endif
}

NOXIR_EXPORT int NOXIR_CALL noxir_request_idr(void)
{
#if defined(_WIN32)
    if (!stream_context.initialized || InterlockedCompareExchange(&stream_context.stopping, 0, 0) != 0)
        return -1;
    return chiaki_session_request_idr(&stream_context.session) == CHIAKI_ERR_SUCCESS ? 0 : -2;
#elif defined(__APPLE__)
    if (!stream_context.initialized || atomic_load(&stream_context.stopping))
        return -1;
    return chiaki_session_request_idr(&stream_context.session) == CHIAKI_ERR_SUCCESS ? 0 : -2;
#else
    return -1;
#endif
}

NOXIR_EXPORT int NOXIR_CALL noxir_register_ps5(
    const char *host,
    const uint8_t *account_id,
    uint32_t device_link_code,
    uint8_t *server_mac,
    char *server_nickname,
    size_t server_nickname_capacity,
    uint8_t *registration_key,
    uint32_t *rp_key_type,
    uint8_t *rp_key,
    char *error_message,
    size_t error_message_capacity)
{
    if (!host || !account_id || !server_mac || !server_nickname || !registration_key || !rp_key_type || !rp_key)
    {
        copy_text(error_message, error_message_capacity, "Eksik PS5 kayıt bilgisi.");
        return -10;
    }

    if (device_link_code > 99999999 || device_link_code < 10000000)
    {
        copy_text(error_message, error_message_capacity, "Cihaz bağlama kodu 8 haneli olmalı.");
        return -10;
    }

    ChiakiErrorCode init_result = chiaki_lib_init();
    if (init_result != CHIAKI_ERR_SUCCESS)
    {
        copy_text(error_message, error_message_capacity, chiaki_error_string(init_result));
        return -11;
    }

    NoxirRegistrationContext context;
    memset(&context, 0, sizeof(context));
#if defined(_WIN32)
    context.completed = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!context.completed)
    {
        copy_text(error_message, error_message_capacity, "PS5 kayıt işlemi başlatılamadı.");
        return -12;
    }
#else
    if (pthread_mutex_init(&context.mutex, NULL) != 0 ||
        pthread_cond_init(&context.cond, NULL) != 0)
    {
        copy_text(error_message, error_message_capacity, "PS5 kayıt işlemi başlatılamadı.");
        return -12;
    }
    context.completed = 0;
#endif

    ChiakiLog log;
    chiaki_log_init(&log, CHIAKI_LOG_ALL, registration_log, &context);

    ChiakiRegistInfo info;
    memset(&info, 0, sizeof(info));
    info.target = CHIAKI_TARGET_PS5_1;
    info.host = host;
    info.broadcast = false;
    memcpy(info.psn_account_id, account_id, CHIAKI_PSN_ACCOUNT_ID_SIZE);
    info.pin = device_link_code;
    info.console_pin = 0;
    info.holepunch_info = NULL;
    info.rudp = NULL;

    ChiakiRegist registration;
    memset(&registration, 0, sizeof(registration));
    ChiakiErrorCode start_result = chiaki_regist_start(&registration, &log, &info, registration_finished, &context);
    if (start_result != CHIAKI_ERR_SUCCESS)
    {
        copy_text(error_message, error_message_capacity, chiaki_error_string(start_result));
#if defined(_WIN32)
        CloseHandle(context.completed);
#else
        pthread_mutex_destroy(&context.mutex);
        pthread_cond_destroy(&context.cond);
#endif
        return -13;
    }

#if defined(_WIN32)
    DWORD wait_result = WaitForSingleObject(context.completed, NOXIR_REGISTRATION_TIMEOUT_MS);
    int timed_out = (wait_result != WAIT_OBJECT_0);
    int wait_failed = (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_TIMEOUT);
#else
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += NOXIR_REGISTRATION_TIMEOUT_MS / 1000;
    deadline.tv_nsec += (long)(NOXIR_REGISTRATION_TIMEOUT_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L)
    {
        deadline.tv_sec += deadline.tv_nsec / 1000000000L;
        deadline.tv_nsec %= 1000000000L;
    }

    pthread_mutex_lock(&context.mutex);
    int wait_timed_out = 0;
    while (!context.completed)
    {
        int rc = pthread_cond_timedwait(&context.cond, &context.mutex, &deadline);
        if (rc == ETIMEDOUT)
        {
            wait_timed_out = 1;
            break;
        }
        if (rc != 0)
        {
            wait_timed_out = 2;
            break;
        }
    }
    pthread_mutex_unlock(&context.mutex);
    int timed_out = wait_timed_out == 1;
    int wait_failed = wait_timed_out == 2;
#endif

    if (timed_out || wait_failed)
    {
        chiaki_regist_stop(&registration);
        copy_text(error_message, error_message_capacity,
                  timed_out ? "PS5 yanıt vermedi. IP adresini ve aynı ağda olduğunu kontrol et." : "PS5 kayıt işlemi kesildi.");
        chiaki_regist_fini(&registration);
#if defined(_WIN32)
        CloseHandle(context.completed);
#else
        pthread_mutex_destroy(&context.mutex);
        pthread_cond_destroy(&context.cond);
#endif
        return timed_out ? -14 : -15;
    }

    chiaki_regist_fini(&registration);
#if defined(_WIN32)
    CloseHandle(context.completed);
#else
    pthread_mutex_destroy(&context.mutex);
    pthread_cond_destroy(&context.cond);
#endif

    if (context.result != 0)
    {
        copy_text(error_message, error_message_capacity,
                  context.last_log_message[0] ? context.last_log_message : "PS5 bu kodla eşleştirilemedi.");
        return context.result;
    }

    memcpy(server_mac, context.host.server_mac, sizeof(context.host.server_mac));
    copy_text(server_nickname, server_nickname_capacity, context.host.server_nickname);
    memcpy(registration_key, context.host.rp_regist_key, sizeof(context.host.rp_regist_key));
    *rp_key_type = context.host.rp_key_type;
    memcpy(rp_key, context.host.rp_key, sizeof(context.host.rp_key));
    copy_text(error_message, error_message_capacity, "");
    return 0;
}
