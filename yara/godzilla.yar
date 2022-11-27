rule Godzilla_PHP_XOR_BASE64 {
	meta:
		description = "Godzilla shell -- PHP_XOR_BASE64 Mode"
		author = "fredflinch"
	strings:
		$php = "<?php" ascii
		$s0 = "@session_start();" ascii
        $s1 = "+1&15" ascii
        $s2 = /encode\(base64_decode\(\$_POST\[\$[\w]{1,}\]\),\$[\w]{1,}\);/
	condition:
		all of them
}

rule inMEM_Godzilla_PHP_XOR_BASE64 {
	meta:
		description = "Godzilla shell -- PHP_XOR_BASE64 Mode -- in memory component"
		author = "fredflinch"
	strings:
		$fname = "function run($pms){" ascii
		$s0 = "(strlen(@trim($dir))>0)?trim($dir):str_replace('\\\\','/',dirname(__FILE__));" ascii
	condition:
		all of them
}