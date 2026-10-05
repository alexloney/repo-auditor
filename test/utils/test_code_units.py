from auditor.utils.code_units import extract_functions, file_preamble, mask_code

def names(source):
    return [u.name for u in extract_functions(source)]

def test_mask_code_blanks_comments_and_strings_preserving_positions():
    src = 'int a = 1; // "x" {\nchar *s = "}"; /* { */\n'
    masked = mask_code(src)
    assert len(masked) == len(src)
    assert masked.count("\n") == src.count("\n")
    assert "{" not in masked and "}" not in masked

def test_extracts_plain_c_functions_with_absolute_lines():
    src = "#include <stdio.h>\n\nstatic int add(int a, int b)\n{\n    return a + b;\n}\n\nvoid f(void) { }\n"
    units = extract_functions(src)
    assert [(u.name, u.start_line, u.end_line) for u in units] == [("add", 3, 6), ("f", 8, 8)]
    assert units[0].text.startswith("static int add")

def test_ignores_control_flow_and_initializers():
    src = (
        "int arr[] = {1, 2, 3};\n"
        "struct S { int x; };\n"
        "void (*handlers[])(int) = { a, b };\n"
        "int main(void) { if (x) { y(); } for (;;) { } return 0; }\n"
    )
    assert names(src) == ["main"]

def test_extracts_class_and_namespace_members():
    src = (
        "namespace ns {\n"
        "class Foo : public Bar {\n"
        "public:\n"
        "    Foo(int x) : a_(x), b_(\"{\") { }\n"
        "    ~Foo() { delete p_; }\n"
        "    int get() const override { return a_; }\n"
        "};\n"
        "}\n"
    )
    assert names(src) == ["Foo", "~Foo", "get"]

def test_extracts_functions_inside_extern_c_blocks():
    src = 'extern "C" {\nint c_api(int x) { return x; }\n}\n'
    assert names(src) == ["c_api"]

def test_extracts_trailing_return_type():
    assert names("auto twice(int x) -> int { return x * 2; }\n") == ["twice"]

def test_comment_before_function_does_not_hijack_name_or_start():
    src = "/* void commented(void) { } */\nstatic void copy(char *d) {\n    d[0] = 0;\n}\n"
    units = extract_functions(src)
    assert [(u.name, u.start_line) for u in units] == [("copy", 2)]

def test_braces_in_strings_and_comments_do_not_break_matching():
    src = 'void f(void) {\n    puts("}");  // }\n    g();\n}\nvoid h(void) { }\n'
    units = extract_functions(src)
    assert [(u.name, u.start_line, u.end_line) for u in units] == [("f", 1, 4), ("h", 5, 5)]

def test_file_preamble_stops_at_first_function():
    src = "#define N 16\ntypedef int T;\nvoid f(void) { }\n"
    assert file_preamble(src, extract_functions(src)) == "#define N 16\ntypedef int T;"

def test_preprocessor_directives_are_not_part_of_the_next_function():
    src = "#define MAX(a, b) \\\n    ((a) > (b) ? (a) : (b))\n#ifdef X\nint g(void) { return 0; }\n#endif\n"
    assert [(u.name, u.start_line) for u in extract_functions(src)] == [("g", 4)]
