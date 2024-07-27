rule HelloWorld {
    strings:
        $text_string = "Hello, world"
    condition:
        $text_string
}
