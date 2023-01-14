rule basic_nodejs_webshell {
    meta:
	    description = "To find basic nodejs 'execution' components that might show up in a shell"
		author = "fredflinch"
    strings:
        $exec = "require(\"child_process\")"
        $excute = " exec(cmd"
        $post_route = ".post("
    condition:
		all of them
}