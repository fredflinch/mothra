rule Godzilla_PHP_XOR_BASE64 {
	meta:
		description = "Godzilla shell -- PHP_XOR_BASE64 Mode"
	strings:
		$php = "<?php" ascii
		$s0 = "@session_start();" ascii
        $s1 = "+1&15" ascii
        $s2 = /encode\(base64_decode\(\$_POST\[\$[\w]{1,}\]\),\$[\w]{1,}\);/
	condition:
		all of them
}