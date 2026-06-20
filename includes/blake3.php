<?php
/**
 * ============================================================
 * Pure-PHP BLAKE3 (validated against official test vectors)
 * ============================================================
 * Provides:
 *   Blake3::hash($data)            -> 32-byte raw
 *   Blake3::hashHex($data)         -> 64-char hex
 *   Blake3::keyed($key32, $data)   -> 32-byte raw (keyed mode)
 *   Blake3::keyedHex($key32, $data)-> 64-char hex
 *
 * No PHP extensions required. Works on shared hosting (Hostinger).
 * Uses 64-bit ints (PHP 7+ on 64-bit systems).
 * ============================================================
 */

class Blake3
{
    private const OUT_LEN   = 32;
    private const KEY_LEN   = 32;
    private const BLOCK_LEN = 64;
    private const CHUNK_LEN = 1024;

    private const CHUNK_START = 1 << 0;
    private const CHUNK_END   = 1 << 1;
    private const PARENT      = 1 << 2;
    private const ROOT        = 1 << 3;
    private const KEYED_HASH  = 1 << 4;

    private const IV = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    private const MSG_PERMUTATION = [
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    ];

    private array $key_words;
    private int   $flags;
    private array $cv_stack = [];
    private array $chunk_state;

    public function __construct(?string $key32 = null)
    {
        if ($key32 === null) {
            $this->key_words = self::IV;
            $this->flags = 0;
        } else {
            if (strlen($key32) !== self::KEY_LEN) {
                throw new InvalidArgumentException('BLAKE3 key must be 32 bytes');
            }
            $this->key_words = array_values(unpack('V8', $key32));
            $this->flags = self::KEYED_HASH;
        }
        $this->chunk_state = [
            'cv' => $this->key_words,
            'counter' => 0,
            'block' => '',
            'blocks_compressed' => 0,
        ];
    }

    public static function hash(string $data): string
    {
        $h = new self();
        $h->update($data);
        return $h->finalize();
    }

    public static function hashHex(string $data): string
    {
        return bin2hex(self::hash($data));
    }

    public static function keyed(string $key32, string $data): string
    {
        $h = new self($key32);
        $h->update($data);
        return $h->finalize();
    }

    public static function keyedHex(string $key32, string $data): string
    {
        return bin2hex(self::keyed($key32, $data));
    }

    public function update(string $data): void
    {
        $i = 0;
        $len = strlen($data);
        while ($i < $len) {
            if ($this->chunkStateLength() === self::CHUNK_LEN) {
                $cv = $this->chunkOutput()['chaining_value'];
                $totalChunks = $this->chunk_state['counter'] + 1;
                $this->addChunkChainingValue($cv, $totalChunks);
                $this->chunk_state = [
                    'cv' => $this->key_words,
                    'counter' => $totalChunks,
                    'block' => '',
                    'blocks_compressed' => 0,
                ];
            }
            $want = self::CHUNK_LEN - $this->chunkStateLength();
            $take = min($want, $len - $i);
            $this->chunkStateUpdate(substr($data, $i, $take));
            $i += $take;
        }
    }

    public function finalize(int $outLen = self::OUT_LEN): string
    {
        $output = $this->chunkOutput();
        $remaining = count($this->cv_stack);
        while ($remaining > 0) {
            $remaining--;
            $output = $this->parentOutput(
                $this->cv_stack[$remaining],
                $output['chaining_value'],
                $this->key_words,
                $this->flags
            );
        }
        return $this->rootOutputBytes($output, $outLen);
    }

    public function finalizeHex(int $outLen = self::OUT_LEN): string
    {
        return bin2hex($this->finalize($outLen));
    }

    private function chunkStateLength(): int
    {
        return $this->chunk_state['blocks_compressed'] * self::BLOCK_LEN
             + strlen($this->chunk_state['block']);
    }

    private function chunkStateStartFlag(): int
    {
        return ($this->chunk_state['blocks_compressed'] === 0) ? self::CHUNK_START : 0;
    }

    private function chunkStateUpdate(string $data): void
    {
        $i = 0;
        $len = strlen($data);
        while ($i < $len) {
            if (strlen($this->chunk_state['block']) === self::BLOCK_LEN) {
                $bw = array_values(unpack('V16', $this->chunk_state['block']));
                $state = self::compress(
                    $this->chunk_state['cv'],
                    $bw,
                    $this->chunk_state['counter'],
                    self::BLOCK_LEN,
                    $this->flags | $this->chunkStateStartFlag()
                );
                $this->chunk_state['cv'] = array_slice($state, 0, 8);
                $this->chunk_state['blocks_compressed']++;
                $this->chunk_state['block'] = '';
            }
            $want = self::BLOCK_LEN - strlen($this->chunk_state['block']);
            $take = min($want, $len - $i);
            $this->chunk_state['block'] .= substr($data, $i, $take);
            $i += $take;
        }
    }

    private function chunkOutput(): array
    {
        $blockLen = strlen($this->chunk_state['block']);
        $padded = $this->chunk_state['block'] . str_repeat("\x00", self::BLOCK_LEN - $blockLen);
        $bw = array_values(unpack('V16', $padded));
        $flags = $this->flags | $this->chunkStateStartFlag() | self::CHUNK_END;
        $cv = array_slice(
            self::compress($this->chunk_state['cv'], $bw, $this->chunk_state['counter'], $blockLen, $flags),
            0, 8
        );
        return [
            'input_cv'       => $this->chunk_state['cv'],
            'block_words'    => $bw,
            'counter'        => $this->chunk_state['counter'],
            'block_len'      => $blockLen,
            'flags'          => $flags,
            'chaining_value' => $cv,
        ];
    }

    private function parentOutput(array $leftCV, array $rightCV, array $keyWords, int $flags): array
    {
        $bw = array_merge($leftCV, $rightCV);
        $f = $flags | self::PARENT;
        $cv = array_slice(self::compress($keyWords, $bw, 0, self::BLOCK_LEN, $f), 0, 8);
        return [
            'input_cv'       => $keyWords,
            'block_words'    => $bw,
            'counter'        => 0,
            'block_len'      => self::BLOCK_LEN,
            'flags'          => $f,
            'chaining_value' => $cv,
        ];
    }

    private function rootOutputBytes(array $output, int $outLen): string
    {
        $out = '';
        $i = 0;
        while (strlen($out) < $outLen) {
            $words = self::compress(
                $output['input_cv'],
                $output['block_words'],
                $i,
                $output['block_len'],
                $output['flags'] | self::ROOT
            );
            foreach ($words as $w) {
                $out .= pack('V', $w & 0xFFFFFFFF);
            }
            $i++;
        }
        return substr($out, 0, $outLen);
    }

    private function addChunkChainingValue(array $newCV, int $totalChunks): void
    {
        while (($totalChunks & 1) === 0) {
            $newCV = $this->parentOutput(
                array_pop($this->cv_stack),
                $newCV,
                $this->key_words,
                $this->flags
            )['chaining_value'];
            $totalChunks >>= 1;
        }
        $this->cv_stack[] = $newCV;
    }

    private static function compress(array $cv, array $blockWords, int $counter, int $blockLen, int $flags): array
    {
        $state = [
            $cv[0], $cv[1], $cv[2], $cv[3],
            $cv[4], $cv[5], $cv[6], $cv[7],
            self::IV[0], self::IV[1], self::IV[2], self::IV[3],
            $counter & 0xFFFFFFFF, ($counter >> 32) & 0xFFFFFFFF, $blockLen, $flags,
        ];
        for ($i = 0; $i < 16; $i++) $state[$i] &= 0xFFFFFFFF;
        $msg = $blockWords;

        for ($r = 0; $r < 7; $r++) {
            self::g($state, 0, 4,  8, 12, $msg[0],  $msg[1]);
            self::g($state, 1, 5,  9, 13, $msg[2],  $msg[3]);
            self::g($state, 2, 6, 10, 14, $msg[4],  $msg[5]);
            self::g($state, 3, 7, 11, 15, $msg[6],  $msg[7]);
            self::g($state, 0, 5, 10, 15, $msg[8],  $msg[9]);
            self::g($state, 1, 6, 11, 12, $msg[10], $msg[11]);
            self::g($state, 2, 7,  8, 13, $msg[12], $msg[13]);
            self::g($state, 3, 4,  9, 14, $msg[14], $msg[15]);

            $permuted = [];
            foreach (self::MSG_PERMUTATION as $idx) $permuted[] = $msg[$idx];
            $msg = $permuted;
        }

        for ($i = 0; $i < 8; $i++) {
            $state[$i]     = ($state[$i]     ^ $state[$i + 8]) & 0xFFFFFFFF;
            $state[$i + 8] = ($state[$i + 8] ^ $cv[$i])         & 0xFFFFFFFF;
        }
        return $state;
    }

    private static function g(array &$s, int $a, int $b, int $c, int $d, int $mx, int $my): void
    {
        $s[$a] = ($s[$a] + $s[$b] + $mx) & 0xFFFFFFFF;
        $s[$d] = self::rotr32($s[$d] ^ $s[$a], 16);
        $s[$c] = ($s[$c] + $s[$d]) & 0xFFFFFFFF;
        $s[$b] = self::rotr32($s[$b] ^ $s[$c], 12);
        $s[$a] = ($s[$a] + $s[$b] + $my) & 0xFFFFFFFF;
        $s[$d] = self::rotr32($s[$d] ^ $s[$a], 8);
        $s[$c] = ($s[$c] + $s[$d]) & 0xFFFFFFFF;
        $s[$b] = self::rotr32($s[$b] ^ $s[$c], 7);
    }

    private static function rotr32(int $v, int $n): int
    {
        $v &= 0xFFFFFFFF;
        return (($v >> $n) | ($v << (32 - $n))) & 0xFFFFFFFF;
    }
}
