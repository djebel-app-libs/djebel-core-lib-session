<?php
/*
lib_id: djebel-core-lib-session
lib_name: Djebel Core Session
version: 1.0.0
description: Session + CSRF helper (Dj_App_Core_Lib_Session) — a hardened, per-app session cookie, namespaced session storage, a per-session CSRF token, and a shutdown GC for its own session dir. Lazily loaded on demand; a consumer starts the session before output.
min_php_ver: 7.4
*/

// A lazy library (loaded on demand via Dj_App_Plugins::loadLib), NOT a plugin — it registers
// no hooks. A consumer loads it and starts the session before any output (djebel buffers the
// whole page, so start-at-render still sets the cookie in time). Singleton — grab the instance,
// then call instance methods:
//   Dj_App_Plugins::loadLib('djebel-core-lib-session');
//   $session_obj = Dj_App_Core_Lib_Session::getInstance();
//   $session_obj->set('my_plugin', 'user_id', 42);  $token = $session_obj->getCsrfToken();
// All reads/writes are NAMESPACED under $_SESSION[<namespace>] — never the $_SESSION root. No
// auto-start: the session only starts when a caller invokes a method, so a request that never
// needs a session pays nothing. A pre-defined / custom impl wins: if the class exists, bail.
if (class_exists('Dj_App_Core_Lib_Session')) {
    return;
}

class Dj_App_Core_Lib_Session
{
    // This plugin keeps its OWN session data (the CSRF token) under this namespace — never at
    // the $_SESSION root, so it can't collide with app / other-plugin keys.
    const SESSION_NAMESPACE = 'djebel_core_session';
    const CSRF_TOKEN_KEY = 'csrf_token';
    // Cookie NAME prefix — names THIS system plugin as the session's owner so the cookie is
    // traceable; the per-app hash is appended so sibling apps get distinct cookies.
    const SESSION_NAME_PREFIX = 'djebel_core_plugin_session';
    // The shutdown session-file GC is scheduled on ~1 in GC_PROBABILITY_DIVISOR requests — the
    // scan is cheap but pointless to run every request.
    const GC_PROBABILITY_DIVISOR = 100;
    // How long a session stays valid — drives the cookie lifetime, gc_maxlifetime, and the runGc
    // prune cutoff. 3 days so a logged-in owner isn't dropped every day.
    const SESSION_LIFETIME = 3 * 24 * 60 * 60;
    // getConfig() field keys — consts so the field names are never magic strings.
    const FIELD_SESSION_NAME = 'session_name';
    const FIELD_LIFETIME = 'lifetime';
    const FIELD_GC_PROBABILITY_DIVISOR = 'gc_probability_divisor';
    const FIELD_SAVE_DIR = 'save_dir';
    const FIELD_COOKIE_PARAMS = 'cookie_params';

    protected $custom_session_name = '';
    // ALL session settings live in one filterable array (see getConfig) — built + filtered once,
    // then memoized here so getSessionName/start/etc. read a single source.
    protected $config = [];

    public static function getInstance()
    {
        static $instance = null;

        if (is_null($instance)) {
            $instance = new static();
        }

        return $instance;
    }

    /**
     * Start a session with a hardened, per-app cookie (HttpOnly, SameSite=Lax, Secure on
     * HTTPS). No-op on CLI, when a session is already active, or after headers are sent.
     * @return bool True when a session is active afterwards.
     */
    public function start()
    {
        if (Dj_App_Env::isCli()) {
            return false;
        }

        if (session_status() == PHP_SESSION_ACTIVE) {
            return true;
        }

        if (headers_sent()) {
            return false;
        }

        $cookie_params = $this->getCookieParams();

        // Fail closed: if the hardened cookie params don't take, do NOT let session_start()
        // fall back to PHP's default (no HttpOnly / no SameSite) session cookie.
        $params_set = session_set_cookie_params($cookie_params);

        if (empty($params_set)) {
            return false;
        }

        // Smart per-app default NAME (derived from the mount path) so two apps on the same
        // host get DISTINCT session cookies even if a filter loosens the path scoping above.
        $session_name = $this->getSessionName();

        if (!empty($session_name)) {
            session_name($session_name);
        }

        // --- Session storage (save_path) ---
        // (a) Defer to a save path a layer already set (server / php.ini / app). Only when
        // NONE is set do we isolate THIS app's session files in its own private tmp dir
        // (reuse getCoreTempDir — never a hardcoded path), lazy-created right before use.
        $we_own_save_dir = false;
        $current_save_dir = session_save_path();

        if (empty($current_save_dir)) {
            $save_dir = $this->getSaveDir();

            if (!empty($save_dir)) {
                $mkdir_res = Dj_App_File_Util::mkdir($save_dir);

                if (!$mkdir_res->isError()) {
                    session_save_path($save_dir);
                    $we_own_save_dir = true;
                }
            }
        }

        // Keep the session valid for the configured lifetime (not PHP's ~24min default) so a
        // logged-in owner isn't dropped mid-day; runGc reads this gc_maxlifetime for its cutoff.
        $lifetime = $this->getLifetime();
        ini_set('session.gc_maxlifetime', $lifetime);

        $started = session_start();

        // A custom save_path is NOT swept by the distro's session-GC cron (which cleans only
        // PHP's default path; session.gc_probability is often 0 there), so our session files
        // would pile up forever. When we own the dir, throttle-register a shutdown GC — it runs
        // AFTER the response via addShutdownAction, so it never blocks the request.
        if (!empty($we_own_save_dir) && !empty($started)) {
            $gc_divisor = $this->getGcProbabilityDivisor();
            $gc_roll = mt_rand(1, $gc_divisor);

            if ($gc_roll == 1) {
                Dj_App_Hooks::addShutdownAction([$this, 'runGc']);
            }
        }

        return $started;
    }

    /**
     * Set a custom session (cookie) name, overriding the per-app default. Call before the
     * session starts (e.g. on app.core.init).
     * @param string $name
     * @return void
     */
    public function setSessionName($name)
    {
        $this->custom_session_name = $name;
        $this->config = [];
    }

    /**
     * ALL session settings in ONE array — session_name, lifetime, gc_probability_divisor,
     * save_dir, cookie_params. Defaults derived from the app's mount path, then the whole array passes
     * through a SINGLE filter so an app can override any/all of it in one place. Built + memoized
     * once ($ctx carries the app mount path so a callback can vary per site).
     * @param string $key  A config field (e.g. 'session_name'); empty returns the whole array.
     * @return mixed  The whole config array, or the named field's value ('' when the field is unset).
     */
    public function getConfig($key = '')
    {
        if (empty($this->config)) {
            $req_obj = Dj_App_Request::getInstance();
            $web_path = $req_obj->getWebPath();
            $is_https = $req_obj->isHttps();

            // Per-app default NAME unless a custom one was set: prefix + hash of the mount path so
            // sibling apps get distinct cookies. The prefix keeps the name non-empty + letter-bearing
            // (PHP regenerates the id for an all-digits name).
            if (!empty($this->custom_session_name)) {
                $name = $this->custom_session_name;
            } else {
                $web_path_hash = Dj_App_Util::generateHash($web_path);
                $name = Dj_App_Core_Lib_Session::SESSION_NAME_PREFIX . '_' . $web_path_hash;
            }

            // This app's own private tmp dir isolates its session files on disk.
            $temp_dir_params = [
                'plugin' => 'djebel-core-plugin-session',
            ];
            $save_dir = Dj_App_Util::getCoreTempDir($temp_dir_params);

            $config = [
                Dj_App_Core_Lib_Session::FIELD_SESSION_NAME => $name,
                Dj_App_Core_Lib_Session::FIELD_LIFETIME => Dj_App_Core_Lib_Session::SESSION_LIFETIME,
                Dj_App_Core_Lib_Session::FIELD_GC_PROBABILITY_DIVISOR => Dj_App_Core_Lib_Session::GC_PROBABILITY_DIVISOR,
                Dj_App_Core_Lib_Session::FIELD_SAVE_DIR => $save_dir,
                // Hardened cookie: HttpOnly + SameSite=Lax + Secure on HTTPS, scoped to this app's
                // mount path so sibling apps can't share/read each other's session. 'lifetime' is
                // added from the top-level 'lifetime' in getCookieParams so the two never drift.
                Dj_App_Core_Lib_Session::FIELD_COOKIE_PARAMS => [
                    'path' => $web_path,
                    'domain' => '',
                    'secure' => $is_https,
                    'httponly' => true,
                    'samesite' => 'Lax',
                ],
            ];

            $ctx = [];
            $ctx['web_path'] = $web_path;

            $config = Dj_App_Hooks::applyFilter('app.core.plugin.session.filter.config', $config, $ctx);

            $this->config = $config;
        }

        // Whole config, or a single field when a key is named.
        if (empty($key)) {
            return $this->config;
        }

        $val = empty($this->config[$key]) ? '' : $this->config[$key];

        return $val;
    }

    /**
     * The session (cookie) name — from the shared config. A name set via setSessionName() wins;
     * otherwise the per-app default (prefix + mount-path hash).
     * @return string
     */
    public function getSessionName()
    {
        $name = $this->getConfig(Dj_App_Core_Lib_Session::FIELD_SESSION_NAME);

        return $name;
    }

    /**
     * How rarely the shutdown session-file GC is scheduled: ~1 in N requests, from the shared
     * config's gc_probability_divisor (a bad value falls back to the default).
     * @return int Always >= 1.
     */
    public function getGcProbabilityDivisor()
    {
        $divisor = $this->getConfig(Dj_App_Core_Lib_Session::FIELD_GC_PROBABILITY_DIVISOR);
        $divisor = (int) $divisor;

        if ($divisor < 1) {
            $divisor = Dj_App_Core_Lib_Session::GC_PROBABILITY_DIVISOR;
        }

        return $divisor;
    }

    /**
     * How long the session stays valid — cookie lifetime + gc_maxlifetime + the runGc cutoff all
     * read this, from the shared config's lifetime (a bad value falls back to the default).
     * @return int Always >= 1.
     */
    public function getLifetime()
    {
        $lifetime = $this->getConfig(Dj_App_Core_Lib_Session::FIELD_LIFETIME);
        $lifetime = (int) $lifetime;

        if ($lifetime < 1) {
            $lifetime = Dj_App_Core_Lib_Session::SESSION_LIFETIME;
        }

        return $lifetime;
    }

    /**
     * The hardened session-cookie params (from the shared config's cookie_params) with the
     * lifetime merged in from the top-level lifetime so the two never drift.
     * @return array
     */
    public function getCookieParams()
    {
        $cookie_params = $this->getConfig(Dj_App_Core_Lib_Session::FIELD_COOKIE_PARAMS);
        $lifetime = $this->getLifetime();

        $cookie_params['lifetime'] = $lifetime;

        return $cookie_params;
    }

    /**
     * The session save directory (from the shared config) — this app's own private tmp dir,
     * isolating its session files on disk. start() applies it only when no save path is set yet.
     * @return string
     */
    public function getSaveDir()
    {
        $save_dir = $this->getConfig(Dj_App_Core_Lib_Session::FIELD_SAVE_DIR);

        return $save_dir;
    }

    /**
     * Read a namespaced value from the session (starts one on demand).
     * @param string $namespace Caller's namespace — keeps its keys off the $_SESSION root.
     * @param string $key
     * @param mixed  $default
     * @return mixed
     */
    public function get($namespace, $key, $default = '')
    {
        $this->start();

        $root = $this->getSessionName();
        $val = isset($_SESSION[$root][$namespace]['data'][$key]) ? $_SESSION[$root][$namespace]['data'][$key] : $default;

        return $val;
    }

    /**
     * Store a namespaced value in the session (starts one on demand). Values live under the
     * caller's namespace + a 'data' section — $_SESSION[root][namespace]['data'][key] — so the
     * caller only ever names a key and never sees the storage layout.
     * @param string $namespace Caller's namespace — keeps its data off the $_SESSION root.
     * @param string $key
     * @param mixed  $val
     * @return bool True if the session is active and the value was stored.
     */
    public function set($namespace, $key, $val)
    {
        $started = $this->start();

        if (empty($started)) {
            return false;
        }

        $root = $this->getSessionName();
        $_SESSION[$root][$namespace]['data'][$key] = $val;

        return true;
    }

    /**
     * Regenerate the session id — call after a privilege change (e.g. a successful login)
     * to prevent session fixation.
     * @return bool True if the id was regenerated.
     */
    public function regenerate()
    {
        $this->start();

        if (session_status() != PHP_SESSION_ACTIVE) {
            return false;
        }

        $regenerated = session_regenerate_id(true);

        return $regenerated;
    }

    /**
     * The per-session CSRF token — generated once with random_bytes, then reused. Stored under
     * this plugin's own session namespace, never the $_SESSION root.
     * @return string
     */
    public function getCsrfToken()
    {
        $token = $this->get(Dj_App_Core_Lib_Session::SESSION_NAMESPACE, Dj_App_Core_Lib_Session::CSRF_TOKEN_KEY);

        if (empty($token)) {
            $random = random_bytes(32);
            $token = bin2hex($random);
            $this->set(Dj_App_Core_Lib_Session::SESSION_NAMESPACE, Dj_App_Core_Lib_Session::CSRF_TOKEN_KEY, $token);
        }

        return $token;
    }

    /**
     * Constant-time check of a submitted token against the session's CSRF token.
     * @param string $token
     * @return bool
     */
    public function verifyCsrfToken($token)
    {
        if (empty($token)) {
            return false;
        }

        $session_token = $this->get(Dj_App_Core_Lib_Session::SESSION_NAMESPACE, Dj_App_Core_Lib_Session::CSRF_TOKEN_KEY);

        if (empty($session_token)) {
            return false;
        }

        $is_valid = hash_equals($session_token, $token);

        return $is_valid;
    }

    /**
     * Tear the session down — clear the data, expire the cookie, destroy it.
     * @return bool True if the session was destroyed.
     */
    public function destroy()
    {
        if (Dj_App_Env::isCli()) {
            return false;
        }

        $this->start();

        $_SESSION = [];

        if (!headers_sent()) {
            $cookie_params = session_get_cookie_params();

            $expire_opts = [
                'expires' => time() - 42000,
                'path' => $cookie_params['path'],
                'domain' => $cookie_params['domain'],
                'secure' => $cookie_params['secure'],
                'httponly' => $cookie_params['httponly'],
            ];

            $session_name = session_name();

            setcookie($session_name, '', $expire_opts);
        }

        if (session_status() != PHP_SESSION_ACTIVE) {
            return false;
        }

        $destroyed = session_destroy();

        return $destroyed;
    }

    /**
     * Shutdown GC for an app-owned session dir. A custom save_path is not swept by the
     * distro's session-GC cron (which cleans only PHP's default path), so we prune expired
     * PHP session files (sess_*) ourselves. Registered via addShutdownAction, so it runs AFTER
     * the response is sent — best-effort, fire-and-forget: the caller ignores the outcome.
     * @return void
     */
    public function runGc()
    {
        $save_dir = session_save_path();

        if (empty($save_dir)) {
            return;
        }

        $max_lifetime = (int) ini_get('session.gc_maxlifetime');

        if (empty($max_lifetime)) {
            $max_lifetime = 1440;
        }

        $now = Dj_App_Util::time();
        $cutoff = $now - $max_lifetime;

        // PHP session files are named sess_<id>; prune only those, older than the cutoff.
        $session_files = glob($save_dir . '/sess_*');
        $session_files = empty($session_files) ? [] : $session_files;

        foreach ($session_files as $session_file) {
            if (!is_file($session_file)) {
                continue;
            }

            $mtime = filemtime($session_file);

            // filemtime() returns false if the file vanished between glob() and now — skip it.
            if ($mtime === false) {
                continue;
            }

            if ($mtime >= $cutoff) {
                continue;
            }

            unlink($session_file);
        }
    }
}
