package internal_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/wal-g/wal-g/internal/compression/lz4"
	"github.com/wal-g/wal-g/internal/compression/lzma"
	"github.com/wal-g/wal-g/internal/config"

	"github.com/wal-g/wal-g/testtools"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/wal-g/wal-g/internal"
)

func TestGetSentinelUserData(t *testing.T) {
	viper.Set(config.SentinelUserDataSetting, "1.0")

	data, err := internal.GetSentinelUserData()
	assert.NoError(t, err)
	t.Log(data)
	assert.Equalf(t, 1.0, data.(float64), "Unable to parse WALG_SENTINEL_USER_DATA")

	viper.Set(config.SentinelUserDataSetting, "\"1\"")

	data, err = internal.GetSentinelUserData()
	assert.NoError(t, err)
	t.Log(data)
	assert.Equalf(t, "1", data.(string), "Unable to parse WALG_SENTINEL_USER_DATA")

	viper.Set(config.SentinelUserDataSetting, `{"x":123,"y":["asdasd",123]}`)

	data, err = internal.GetSentinelUserData()
	assert.NoError(t, err)
	t.Log(data)
	assert.NotNilf(t, data, "Unable to parse WALG_SENTINEL_USER_DATA")

	viper.Set(config.SentinelUserDataSetting, `"x",1`)

	data, err = internal.GetSentinelUserData()
	assert.Error(t, err, "Should fail on the invalid user data")
	t.Log(err)
	assert.Nil(t, data)
	resetToDefaults()
}

func TestGetDataFolderPath_Default(t *testing.T) {
	pgEnv := os.Getenv(config.PgDataSetting)
	os.Unsetenv(config.PgDataSetting)
	// ensure the PgData environment variable is not set bc if it is set, viper returns it. viper.Set(..., nil) does not
	// "override" the environment variable. Likely a bug in viper: https://github.com/spf13/viper/blob/528f7416c4b56a4948673984b190bf8713f0c3c4/viper.go#L1212-L1216
	// some environments actually have PGDATA set _with_ proper structure (C:\PostgreSQL\17\data\pg_wal) and tests
	// fail because of that
	resetToDefaults()
	viper.Set(config.PgDataSetting, nil)

	actual := internal.GetDataFolderPath()

	assert.Equal(t, path.Join(internal.GetDefaultDataFolderPath(), "walg_data"), actual)
	os.Setenv(config.PgDataSetting, pgEnv)
	resetToDefaults()
}

func TestGetDataFolderPath_FolderNotExist(t *testing.T) {
	parentDir := prepareDataFolder(t, "someOtherFolder")
	defer testtools.Cleanup(t, parentDir)

	viper.Set(config.PgDataSetting, parentDir)

	actual := internal.GetDataFolderPath()

	assert.Equal(t, path.Join(internal.GetDefaultDataFolderPath(), "walg_data"), actual)
	resetToDefaults()
}

func TestGetDataFolderPath_Wal(t *testing.T) {
	parentDir := prepareDataFolder(t, "pg_wal")
	defer testtools.Cleanup(t, parentDir)

	viper.Set(config.PgDataSetting, parentDir)

	actual := internal.GetDataFolderPath()

	assert.Equal(t, filepath.ToSlash(filepath.Join(parentDir, "pg_wal", "walg_data")), actual)
	resetToDefaults()
}

func TestGetDataFolderPath_Xlog(t *testing.T) {
	parentDir := prepareDataFolder(t, "pg_xlog")
	defer testtools.Cleanup(t, parentDir)

	viper.Set(config.PgDataSetting, parentDir)

	actual := internal.GetDataFolderPath()

	assert.Equal(t, filepath.ToSlash(filepath.Join(parentDir, "pg_xlog", "walg_data")), actual)
	resetToDefaults()
}

func TestGetDataFolderPath_WalIgnoreXlog(t *testing.T) {
	parentDir := prepareDataFolder(t, "pg_xlog")
	defer testtools.Cleanup(t, parentDir)

	err := os.Mkdir(filepath.Join(parentDir, "pg_wal"), 0700)
	if err != nil {
		t.Log(err)
	}
	viper.Set(config.PgDataSetting, parentDir)

	actual := internal.GetDataFolderPath()

	assert.Equal(t, filepath.ToSlash(filepath.Join(parentDir, "pg_wal", "walg_data")), actual)
	resetToDefaults()
}

func TestConfigureCompressor_Lz4Method(t *testing.T) {
	viper.Set(config.CompressionMethodSetting, "lz4")
	compressor, err := internal.ConfigureCompressor()
	assert.NoError(t, err)
	assert.Equal(t, compressor, lz4.Compressor{})
	resetToDefaults()
}

func TestConfigureCompressor_LzmaMethod(t *testing.T) {
	viper.Set(config.CompressionMethodSetting, "lzma")
	compressor, err := internal.ConfigureCompressor()
	assert.NoError(t, err)
	assert.Equal(t, compressor, lzma.Compressor{})
	resetToDefaults()
}

func TestConfigureCompressor_UseDefaultOnNoMethodSet(t *testing.T) {
	compressor, err := internal.ConfigureCompressor()
	assert.NoError(t, err)
	assert.Equal(t, compressor, lz4.Compressor{})
	resetToDefaults()
}

func TestConfigureCompressor_ErrorWhenViperClear(t *testing.T) {
	viper.Reset()
	compressor, err := internal.ConfigureCompressor()
	assert.Error(t, err)
	assert.Equal(t, compressor, nil)
	resetToDefaults()
}

func TestConfigureCompressor_FailsOnInvalidCompressorString(t *testing.T) {
	viper.Set(config.CompressionMethodSetting, "kek123kek")
	compressor, err := internal.ConfigureCompressor()
	assert.Error(t, err)
	assert.Equal(t, compressor, nil)
	resetToDefaults()
}

// TestConfigureCrypter_AgeMultiRecipient asserts the grunt-it age crypter is
// selected from WALG_AGE_* settings AND that a blob encrypted to two recipients
// round-trips with EITHER identity — the end-to-end wiring proof for wal-g#1983.
func TestConfigureCrypter_AgeMultiRecipient(t *testing.T) {
	humanID, err := age.GenerateX25519Identity()
	assert.NoError(t, err)
	drillID, err := age.GenerateX25519Identity()
	assert.NoError(t, err)

	dir := t.TempDir()
	recipientFile := filepath.Join(dir, "age-recipient.pub")
	contents := humanID.Recipient().String() + "\n" + drillID.Recipient().String() + "\n"
	assert.NoError(t, os.WriteFile(recipientFile, []byte(contents), 0o644))

	// Upload-side crypter: recipient file only.
	viper.Set(config.AgeRecipientPathSetting, recipientFile)
	crypter, err := internal.ConfigureCrypterForSpecificConfig(viper.GetViper())
	assert.NoError(t, err)
	assert.NotNil(t, crypter)
	assert.Equal(t, "age", crypter.Name())

	var buf bytes.Buffer
	w, err := crypter.Encrypt(&buf)
	assert.NoError(t, err)
	_, err = w.Write([]byte("walg-age-wiring-marker"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())
	resetToDefaults()

	// Download-side crypter with the DRILL identity decrypts the same blob.
	viper.Set(config.AgeIdentitySetting, drillID.String())
	dcrypter, err := internal.ConfigureCrypterForSpecificConfig(viper.GetViper())
	assert.NoError(t, err)
	assert.Equal(t, "age", dcrypter.Name())
	r, err := dcrypter.Decrypt(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, "walg-age-wiring-marker", string(out))
	resetToDefaults()
}

func prepareDataFolder(t *testing.T, name string) string {
	cwd, err := filepath.Abs("./")
	if err != nil {
		t.Log(err)
	}
	// Create temp Directory.
	dir, err := os.MkdirTemp(cwd, "test")
	if err != nil {
		t.Log(err)
	}
	err = os.Mkdir(filepath.Join(dir, name), 0700)
	if err != nil {
		t.Log(err)
	}
	fmt.Println(dir)
	return dir
}

func resetToDefaults() {
	viper.Reset()
	internal.ConfigureSettings(config.PG)
	config.InitConfig()
	config.Configure()
}
