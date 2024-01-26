<?php

namespace OAuth2\Storage;

class Bootstrap
{
    const DYNAMODB_PHP_VERSION = 'none';

    protected static $instance;
    private $mysql;
    private $sqlite;
    private $postgres;
    private $mongo;
    private $mongoDb;
    private $redis;
    private $cassandra;
    private $configDir;
    private $dynamodb;
    private $couchbase;

    public function __construct()
    {
        $this->configDir = __DIR__ . '/../../../config';
    }

    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function getSqlitePdo()
    {
        if (!$this->sqlite) {
            $this->removeSqliteDb();
            $pdo = new \PDO(sprintf('sqlite:%s', $this->getSqliteDir()));
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            $this->createSqliteDb($pdo);

            $this->sqlite = new Pdo($pdo);
        }

        return $this->sqlite;
    }

    public function getPostgresPdo()
    {
        if (!$this->postgres) {
            if (in_array('pgsql', \PDO::getAvailableDrivers())) {
                $this->removePostgresDb();
                $this->createPostgresDb();
                if ($pdo = $this->getPostgresDriver()) {
                    $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
                    $this->populatePostgresDb($pdo);
                    $this->postgres = new Pdo($pdo);
                }
            } else {
                $this->postgres = new NullStorage('Postgres', 'Missing postgres PDO extension.');
            }
        }

        return $this->postgres;
    }

    public function getPostgresDriver()
    {
        try {
            $pdo = new \PDO('pgsql:host=localhost;dbname=oauth2_server_php', 'postgres', 'postgres');

            return $pdo;
        } catch (\PDOException $e) {
            $this->postgres = new NullStorage('Postgres', $e->getMessage());
        }
    }

    public function getMemoryStorage()
    {
        return new Memory(json_decode(file_get_contents($this->configDir . '/storage.json'), true));
    }

    public function getRedisStorage()
    {
        if (!$this->redis) {
            if (class_exists('Predis\Client')) {
                $redis = new \Predis\Client();
                if ($this->testRedisConnection($redis)) {
                    $redis->flushdb();
                    $this->redis = new Redis($redis);
                    $this->createRedisDb($this->redis);
                } else {
                    $this->redis = new NullStorage('Redis', 'Unable to connect to redis server on port 6379');
                }
            } else {
                $this->redis = new NullStorage('Redis', 'Missing redis library. Please run "composer.phar require predis/predis:dev-master"');
            }
        }

        return $this->redis;
    }

    private function testRedisConnection(\Predis\Client $redis)
    {
        try {
            $redis->connect();
        } catch (\Predis\CommunicationException $exception) {
            // we were unable to connect to the redis server
            return false;
        }

        return true;
    }

    public function getMysqlPdo()
    {
        if (!$this->mysql) {
            $pdo = null;
            try {
                $pdo = new \PDO('mysql:host=localhost;', 'root', 'root');
            } catch (\PDOException $e) {
                $this->mysql = new NullStorage('MySQL', 'Unable to connect to MySQL on root@localhost');
            }

            if ($pdo) {
                $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
                $this->removeMysqlDb($pdo);
                $this->createMysqlDb($pdo);

                $this->mysql = new Pdo($pdo);
            }
        }

        return $this->mysql;
    }

    private function createSqliteDb(\PDO $pdo)
    {
        $this->runPdoSql($pdo);
    }

    private function removeSqliteDb()
    {
        if (file_exists($this->getSqliteDir())) {
            unlink($this->getSqliteDir());
        }
    }

    private function createMysqlDb(\PDO $pdo)
    {
        $pdo->exec('CREATE DATABASE oauth2_server_php');
        $pdo->exec('USE oauth2_server_php');
        $this->runPdoSql($pdo);
    }

    private function removeMysqlDb(\PDO $pdo)
    {
        $pdo->exec('DROP DATABASE IF EXISTS oauth2_server_php');
    }

    private function createPostgresDb()
    {
        if (!`PGPASSWORD=postgres psql postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='postgres'" -h localhost -U postgres`) {
            `PGPASSWORD=postgres createuser -s -r postgres -h localhost -U postgres`;
        }

        `PGPASSWORD=postgres createdb -O postgres oauth2_server_php -h localhost -U postgres`;
    }

    private function populatePostgresDb(\PDO $pdo)
    {
        $this->runPdoSql($pdo);
    }

    private function removePostgresDb()
    {
        if (trim(`PGPASSWORD=postgres psql -l -h localhost -U postgres | grep oauth2_server_php | wc -l`)) {
            `PGPASSWORD=postgres dropdb oauth2_server_php -h localhost -U postgres`;
        }
    }

    public function runPdoSql(\PDO $pdo)
    {
        $storage = new Pdo($pdo);
        foreach (explode(';', $storage->getBuildSql()) as $statement) {
            $result = $pdo->exec($statement);
        }

        // set up scopes
        $sql = 'INSERT INTO oauth_scopes (scope) VALUES (?)';
        foreach (explode(' ', 'supportedscope1 supportedscope2 supportedscope3 supportedscope4 clientscope1 clientscope2 clientscope3') as $supportedScope) {
            $pdo->prepare($sql)->execute(array($supportedScope));
        }

        $sql = 'INSERT INTO oauth_scopes (scope, is_default) VALUES (?, ?)';
        foreach (array('defaultscope1', 'defaultscope2') as $defaultScope) {
            $pdo->prepare($sql)->execute(array($defaultScope, true));
        }

        // set up clients
        $sql = 'INSERT INTO oauth_clients (client_id, client_secret, scope, grant_types, backchannel_logout_uri, backchannel_logout_session_required) VALUES (?, ?, ?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('Test Client ID', 'TestSecret', 'clientscope1 clientscope2', null, null, false));
        $pdo->prepare($sql)->execute(array('Test Client ID 2', 'TestSecret', 'clientscope1 clientscope2 clientscope3', null, null, false));
        $pdo->prepare($sql)->execute(array('Test Default Scope Client ID', 'TestSecret', 'clientscope1 clientscope2', null, null, false));
        $pdo->prepare($sql)->execute(array('oauth_test_client', 'testpass', null, 'implicit password', null, false));
        $pdo->prepare($sql)->execute(array('Test Client Backchannel Logout', 'TestSecret', null, 'authorization_code', 'https://example.org', false));
        $pdo->prepare($sql)->execute(array('Test Client Backchannel Logout No Uri', 'TestSecret', null, 'authorization_code', null, false));

        // set up misc
        $sql = 'INSERT INTO oauth_access_tokens (access_token, client_id, expires, user_id) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('testtoken', 'Some Client', date('Y-m-d H:i:s', strtotime('+1 hour')), null));
        $pdo->prepare($sql)->execute(array('accesstoken-openid-connect', 'Some Client', date('Y-m-d H:i:s', strtotime('+1 hour')), 'testuser'));
        $pdo->prepare($sql)->execute(array('testcode3', 'Test Client Backchannel Logout No Uri', date('Y-m-d H:i:s', strtotime('+1 hour')), 'testuser'));

        $sql = 'INSERT INTO oauth_authorization_codes (authorization_code, client_id, expires, user_id) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('testcode', 'Some Client', date('Y-m-d H:i:s', strtotime('+1 hour')), null));
        $pdo->prepare($sql)->execute(array('testcode2', 'Test Client Backchannel Logout', date('Y-m-d H:i:s', strtotime('+1 hour')), 'abcd123'));
        $pdo->prepare($sql)->execute(array('testcode3', 'Test Client Backchannel Logout No Uri', date('Y-m-d H:i:s', strtotime('+1 hour')), null));

        $sql = 'INSERT INTO oauth_users (username, password, email, email_verified) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('testuser', 'password', 'testuser@test.com', true));

        $sql = 'INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('ClientID_One', 'client_1_public', 'client_1_private', 'RS256'));
        $pdo->prepare($sql)->execute(array('ClientID_Two', 'client_2_public', 'client_2_private', 'RS256'));

        $sql = 'INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array(null, $this->getTestPublicKey(), $this->getTestPrivateKey(), 'RS256'));

        $sql = 'INSERT INTO oauth_jwt (client_id, subject, public_key) VALUES (?, ?, ?)';
        $pdo->prepare($sql)->execute(array('oauth_test_client', 'test_subject', $this->getTestPublicKey()));
    }

    public function getSqliteDir()
    {
        return $this->configDir . '/test.sqlite';
    }

    public function getConfigDir()
    {
        return $this->configDir;
    }

    private function createRedisDb(Redis $storage)
    {
        $storage->setClientDetails("oauth_test_client", "testpass", "http://example.com", 'implicit password');
        $storage->setAccessToken("testtoken", "Some Client", '', time() + 1000);
        $storage->setAuthorizationCode("testcode", "Some Client", '', '', time() + 1000);
        $storage->setUser("testuser", "password");

        $storage->setScope('supportedscope1 supportedscope2 supportedscope3 supportedscope4');
        $storage->setScope('defaultscope1 defaultscope2', null, 'default');

        $storage->setScope('clientscope1 clientscope2', 'Test Client ID');
        $storage->setScope('clientscope1 clientscope2', 'Test Client ID', 'default');

        $storage->setScope('clientscope1 clientscope2 clientscope3', 'Test Client ID 2');
        $storage->setScope('clientscope1 clientscope2', 'Test Client ID 2', 'default');

        $storage->setScope('clientscope1 clientscope2', 'Test Default Scope Client ID');
        $storage->setScope('clientscope1 clientscope2', 'Test Default Scope Client ID', 'default');

        $storage->setScope('clientscope1 clientscope2 clientscope3', 'Test Default Scope Client ID 2');
        $storage->setScope('clientscope3', 'Test Default Scope Client ID 2', 'default');

        $storage->setClientKey('oauth_test_client', $this->getTestPublicKey(), 'test_subject');
    }

    public function getTestPublicKey()
    {
        return file_get_contents(__DIR__ . '/../../../config/keys/id_rsa.pub');
    }

    private function getTestPrivateKey()
    {
        return file_get_contents(__DIR__ . '/../../../config/keys/id_rsa');
    }

    private function getEnvVar($var, $default = null)
    {
        return isset($_SERVER[$var]) ? $_SERVER[$var] : (getenv($var) ?: $default);
    }
}
