<?php

// Validate complete catalogs and Roundcube's real language/fallback loader.
$root = dirname(__DIR__);
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
$base = $roundcube_root . '/program/lib/Roundcube/rcube.php';
if (!is_file($base)) {
    throw new RuntimeException('Set ROUNDCUBE_ROOT to a development Roundcube installation.');
}
require $base;
if (!function_exists('slashify')) {
    function slashify($path) { return rtrim($path, '/\\') . '/'; }
}

$checks = 0;
function localization_check($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}
function localization_catalog($file)
{
    $labels = $messages = [];
    require $file;
    return ['labels' => $labels, 'messages' => $messages];
}
function localization_keys($values)
{
    $keys = array_keys($values);
    sort($keys);
    return $keys;
}
function localization_variables($text)
{
    preg_match_all('/\$[A-Za-z_][A-Za-z0-9_]*/', $text, $matches);
    sort($matches[0]);
    return $matches[0];
}

$metadata = json_decode(file_get_contents($root . '/tests/locales.json'), true, 512, JSON_THROW_ON_ERROR);
$source = localization_catalog($root . '/localization/en_US.inc');
$source_texts = array_merge($source['labels'], $source['messages']);
$loader = (new ReflectionClass('rcube'))->newInstanceWithoutConstructor();
localization_check(count($metadata['locales']) === 86, 'Roundcube locale inventory changed');
$catalog_count = 0;
foreach ($metadata['locales'] as $locale => $entry) {
    $file = $root . '/localization/' . $locale . '.inc';
    if (in_array($entry['status'], ['english-fallback', 'native-regional-fallback'], true)) {
        localization_check(!is_file($file), "$locale must use the documented native fallback");
    } else {
        $catalog_count++;
        localization_check(is_file($file), "$locale catalog missing");
        $bytes = file_get_contents($file);
        localization_check(substr($bytes, 0, 3) !== "\xEF\xBB\xBF" && preg_match('//u', $bytes) === 1, "$locale must be UTF-8 without BOM");
        $catalog = localization_catalog($file);
        foreach ($source as $group => $values) {
            localization_check(localization_keys($catalog[$group]) === localization_keys($values), "$locale/$group keys differ");
            foreach ($values as $key => $value) {
                $translated = $catalog[$group][$key];
                localization_check(is_string($translated) && trim($translated) !== '', "$locale/$key is empty");
                localization_check(localization_variables($translated) === localization_variables($value), "$locale/$key placeholders changed");
                localization_check(strpos($translated, '987654321') === false && strpos($translated, '__RC_') === false, "$locale/$key has a translation marker");
            }
        }
    }

    $loaded = $loader->read_localization($root . '/localization/', $locale);
    localization_check(localization_keys($loaded) === localization_keys($source_texts), "$locale missing text through native loader");
    if ($entry['status'] === 'english-fallback') {
        localization_check($loaded === $source_texts, "$locale English fallback failed");
    } elseif ($entry['status'] === 'native-regional-fallback') {
        $fallback = $loader->read_localization($root . '/localization/', $entry['fallback']);
        localization_check($loaded === $fallback, "$locale regional fallback failed");
    }
}
localization_check($catalog_count === 80, 'Catalog coverage changed');
localization_check(count(glob($root . '/localization/*.inc')) === $catalog_count, 'Undocumented locale catalog');
echo "Localization: $checks checks passed (80 catalogs, 86 native locale loads).\n";
