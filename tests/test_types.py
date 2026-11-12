import re
from fnmatch import fnmatchcase
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest

from sigma.exceptions import (
    SigmaCIDRExpansionError,
    SigmaPlaceholderError,
    SigmaTypeError,
    SigmaValueError,
    SigmaRegularExpressionError,
)
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaFieldReference,
    SigmaRegularExpressionFlag,
    SigmaString,
    Placeholder,
    SpecialChars,
    SigmaNumber,
    SigmaNull,
    SigmaRegularExpression,
    SigmaQueryExpression,
    sigma_type,
    SigmaCIDRExpression,
)


@pytest.fixture
def sigma_string():
    return SigmaString("*Test*Str\\*ing*")


@pytest.fixture
def empty_sigma_string():
    return SigmaString("")


def test_strings_empty():
    assert SigmaString().s == []


def test_strings_plain():
    assert SigmaString("plain").s == ["plain"]


def test_strings_merge():
    s = SigmaString()
    s.s = [SpecialChars.WILDCARD_MULTI, "te", "st", SpecialChars.WILDCARD_MULTI]
    assert s._merge_strs().s == [
        SpecialChars.WILDCARD_MULTI,
        "test",
        SpecialChars.WILDCARD_MULTI,
    ]


def test_strings_merge_end():
    s = SigmaString()
    s.s = [
        SpecialChars.WILDCARD_MULTI,
        "test",
        SpecialChars.WILDCARD_MULTI,
        "te",
        "st",
        "test",
    ]
    assert s._merge_strs().s == [
        SpecialChars.WILDCARD_MULTI,
        "test",
        SpecialChars.WILDCARD_MULTI,
        "testtest",
    ]


def test_strings_merge_start():
    s = SigmaString()
    s.s = [
        "te",
        "st",
        "test",
        SpecialChars.WILDCARD_MULTI,
        "test",
        SpecialChars.WILDCARD_MULTI,
    ]
    assert s._merge_strs().s == [
        "testtest",
        SpecialChars.WILDCARD_MULTI,
        "test",
        SpecialChars.WILDCARD_MULTI,
    ]


def test_strings_wildcards():
    assert SigmaString("wild*cards?contained").s == [
        "wild",
        SpecialChars.WILDCARD_MULTI,
        "cards",
        SpecialChars.WILDCARD_SINGLE,
        "contained",
    ]


def test_strings_escaping():
    assert SigmaString("escaped\\*\\?\\\\*?").s == [
        "escaped*?\\",
        SpecialChars.WILDCARD_MULTI,
        SpecialChars.WILDCARD_SINGLE,
    ]


def test_strings_escaping_nonspecial():
    assert SigmaString("escaped\\nonspecial").s == ["escaped\\nonspecial"]


def test_strings_escaping_end():
    assert SigmaString("finalescape\\").s == ["finalescape\\"]


def test_strings_from_str():
    assert SigmaString.from_str("test*string\\\\") == SigmaString("test\\*string\\\\\\\\")


def test_string_placeholders_single():
    assert SigmaString("test1%var%test2").insert_placeholders().s == [
        "test1",
        Placeholder("var"),
        "test2",
    ]


def test_string_placeholders_multi():
    assert SigmaString("%start%te*st1%middle%te?st2%end%").insert_placeholders().s == [
        Placeholder("start"),
        "te",
        SpecialChars.WILDCARD_MULTI,
        "st1",
        Placeholder("middle"),
        "te",
        SpecialChars.WILDCARD_SINGLE,
        "st2",
        Placeholder("end"),
    ]


def test_string_replace_with_placeholder():
    assert SigmaString("testx1xfoox1xtest*x2x*bar*x3x").replace_with_placeholder(
        re.compile("x\\dx"), "test"
    ).s == [
        "test",
        Placeholder("test"),
        "foo",
        Placeholder("test"),
        "test",
        SpecialChars.WILDCARD_MULTI,
        Placeholder("test"),
        SpecialChars.WILDCARD_MULTI,
        "bar",
        SpecialChars.WILDCARD_MULTI,
        Placeholder("test"),
    ]


def test_string_placeholders_replace():
    def callback(p):
        yield from ["A", SpecialChars.WILDCARD_MULTI]

    assert SigmaString("test%var1%something%var2%end").insert_placeholders().replace_placeholders(
        callback
    ) == [
        SigmaString("testAsomethingAend"),
        SigmaString("testAsomething*end"),
        SigmaString("test*somethingAend"),
        SigmaString("test*something*end"),
    ]


def test_string_placeholders_replace_max_expansion():
    with pytest.raises(SigmaValueError, match="Placeholder expansion exceeds maximum of 200 items"):
        (
            SigmaString("%a%%b%%c%%d%")
            .insert_placeholders()
            .replace_placeholders(lambda p: iter(["0", "1", "2", "3"]))
        )


def test_string_placeholders_escape():
    # Backslashes before % signs are kept as literal characters; the placeholder %var%
    # is still found because it has no backslash before its closing %.
    assert SigmaString("\\%test1\\%test2\\%%var%\\%test3\\%").insert_placeholders().s == [
        "\\%test1\\%test2\\%",
        Placeholder("var"),
        "\\%test3\\%",
    ]


def test_string_placeholders_escape_percent():
    """\\% keeps both the backslash and the percent as literals when the name is invalid."""
    assert SigmaString("\\%foo\\%").insert_placeholders().s == ["\\%foo\\%"]


def test_string_placeholders_escaped_backslash_before_placeholder():
    """\\\\% in the Sigma rule is a literal \\ followed by a placeholder."""
    result = SigmaString("\\\\%foo%").insert_placeholders()
    assert result.s == ["\\", Placeholder("foo")]


def test_string_placeholders_escaped_backslash_in_value():
    """\\\\%name% expands correctly when placeholder is replaced with values."""
    result = SigmaString("\\\\%foo%").insert_placeholders()
    expanded = result.replace_placeholders(
        lambda ph: iter(["bar", "baz"]) if ph.name == "foo" else iter([ph])
    )
    assert [str(v) for v in expanded] == ["\\bar", "\\baz"]


def test_string_contains_placeholders():
    assert SigmaString("test1%var%test2").insert_placeholders().contains_placeholder()


def test_string_contains_placeholders_none():
    assert SigmaString("test1test2").insert_placeholders().contains_placeholder() == False


def test_string_contains_placeholders_included():
    assert (
        SigmaString("test1%var%test2%test%")
        .insert_placeholders()
        .contains_placeholder(include=["var"])
    )


def test_string_contains_placeholders_no_included():
    assert (
        SigmaString("test1%var%test2%test%")
        .insert_placeholders()
        .contains_placeholder(include=["other"])
        == False
    )


def test_string_contains_placeholders_one_excluded():
    assert (
        SigmaString("test1%var%test2%test%")
        .insert_placeholders()
        .contains_placeholder(exclude=["var"])
    )


def test_string_contains_placeholders_all_excluded():
    assert (
        SigmaString("test1%var%test2%test%")
        .insert_placeholders()
        .contains_placeholder(exclude=["var", "test"])
        == False
    )


def test_string_placeholders_with_dot():
    """Test placeholders with dots in names"""
    assert SigmaString("test%var.name%end").insert_placeholders().s == [
        "test",
        Placeholder("var.name"),
        "end",
    ]


def test_strings_equal():
    assert SigmaString("test*string") == SigmaString("test*string")


def test_strings_not_equal():
    assert SigmaString("test\\*string") != SigmaString("test*string")


def test_strings_equal_str():
    assert SigmaString("test*string") == "test*string"


def test_strings_not_equal_str():
    assert SigmaString("test\\*string") != "test*string"


def test_strings_equal_invalid_type():
    with pytest.raises(NotImplementedError):
        SigmaString("123") == 123


def test_strings_startswith_str():
    assert SigmaString("foobar").startswith("foo")


def test_strings_startswith_empty():
    assert not SigmaString("").startswith("abc")


def test_strings_startswith_special():
    assert SigmaString("*foobar").startswith(SpecialChars.WILDCARD_MULTI)


def test_strings_startswith_difftypes():
    assert not SigmaString("*foobar").startswith("foo")


def test_strings_endswith_str():
    assert SigmaString("foobar").endswith("bar")


def test_strings_endswith_empty():
    assert not SigmaString("").endswith("abc")


def test_strings_endswith_special():
    assert SigmaString("foobar*").endswith(SpecialChars.WILDCARD_MULTI)


def test_strings_endswith_difftypes():
    assert not SigmaString("foobar*").endswith("bar")


def test_strings_contains_special():
    assert SigmaString("foo*bar").contains_special()


def test_strings_not_contains_special():
    assert not SigmaString("foobar").contains_special()


def test_strings_add_sigmastring():
    assert SigmaString("*foo?") + SigmaString("bar*") == SigmaString("*foo?bar*")


def test_strings_add_lstr():
    assert "*foo?" + SigmaString("?bar*") == SigmaString("\\*foo\\??bar*")


def test_strings_add_rstr():
    assert SigmaString("*foo?") + "?bar*" == SigmaString("*foo?\\?bar\\*")


def test_strings_add_linvalid():
    with pytest.raises(TypeError):
        123 + SigmaString("foo")


def test_strings_add_rinvalid():
    with pytest.raises(TypeError):
        SigmaString("foo") + 123


def test_strings_add_lspecial():
    assert SpecialChars.WILDCARD_MULTI + SigmaString("foo*") == SigmaString("*foo*")


def test_strings_add_rspecial():
    assert SigmaString("*foo") + SpecialChars.WILDCARD_MULTI == SigmaString("*foo*")


def test_strings_to_string():
    assert str(SigmaString("test*?")) == "test*?"


def test_strings_with_plain_wildcards_to_string():
    plain_s = r"value\*with\?plain*wild?cards"
    s = SigmaString(plain_s)
    assert s.s == [
        "value*with?plain",
        SpecialChars.WILDCARD_MULTI,
        "wild",
        SpecialChars.WILDCARD_SINGLE,
        "cards",
    ]
    assert str(s) == plain_s
    assert SigmaString(str(s)) == s


def test_strings_with_placeholder_to_string():
    assert str(SigmaString("te%var%st").insert_placeholders()) == "te%var%st"


def test_strings_to_plain():
    assert SigmaString("test*?").to_plain() == "test*?"


def test_strings_to_plain_escape_backslash():
    s = SigmaString("C:\\Temp\\") + SpecialChars.WILDCARD_MULTI
    assert s.to_plain() == "C:\\Temp\\*"  # default unchanged
    assert s.to_plain(escape_backslash=True) == "C:\\Temp\\\\*"


@pytest.mark.parametrize(
    "parts",
    [
        ["a\\", SpecialChars.WILDCARD_MULTI],
        ["a\\", SpecialChars.WILDCARD_SINGLE, "b"],
        ["a\\*b"],
        ["a\\?b"],
        ["\\\\server\\share"],
        ["a\\\\", SpecialChars.WILDCARD_MULTI],
        ["C:\\Temp\\"],
        ["\\"],
        ["a\\", Placeholder("p"), "\\"],
        [SpecialChars.WILDCARD_MULTI, "\\x\\", SpecialChars.WILDCARD_SINGLE],
    ],
)
def test_strings_to_plain_escape_backslash_roundtrip(parts):
    s = SigmaString()
    s.s = parts
    assert SigmaString(s.to_plain(escape_backslash=True)).insert_placeholders() == s


def test_strings_to_bytes():
    assert bytes(SigmaString("test*?")) == b"test*?"


def test_strings_to_bytes_escaped_wildcards():
    # Escaped wildcards are literal characters of the value: the escaping is not encoded.
    assert bytes(SigmaString("x\\*y\\?z")) == b"x*y?z"


def test_strings_len(sigma_string):
    assert len(sigma_string) == 14


def test_strings_iter():
    assert list(SigmaString("foo*bar")) == [
        "f",
        "o",
        "o",
        SpecialChars.WILDCARD_MULTI,
        "b",
        "a",
        "r",
    ]


def test_strings_convert():
    assert SigmaString("foo?\\*bar*").convert(add_escaped="f", filter_chars="o") == "\\f?\\*bar*"


def test_strings_convert_no_multiwildcard():
    with pytest.raises(SigmaValueError, match="Multi-character wildcard"):
        SigmaString("foo*bar").convert(wildcard_multi=None)


def test_strings_convert_no_singlewildcard():
    with pytest.raises(SigmaValueError, match="Single-character wildcard"):
        SigmaString("foo?bar").convert(wildcard_single=None)


def test_strings_convert_placeholder():
    with pytest.raises(SigmaPlaceholderError, match="unhandled placeholder 'var'"):
        SigmaString("foo%var%bar").insert_placeholders().convert()


def test_strings_convert_invalid_part():
    s = SigmaString("test")
    s.s = ["test", 1]
    with pytest.raises(SigmaValueError, match="part of type 'int'"):
        s.convert()


def test_strings_to_regex():
    s = SigmaString("Test*Special?(Plain)/[\\*\\?]")
    assert s.s == [
        "Test",
        SpecialChars.WILDCARD_MULTI,
        "Special",
        SpecialChars.WILDCARD_SINGLE,
        "(Plain)/[*?]",
    ]
    r = s.to_regex()
    assert str(r.regexp) == "Test.*Special.\\(Plain\\)/\\[\\*\\?\\]"


def test_strings_to_regex_with_additional_escape_chars():
    s = SigmaString("Test*Special?(Plain)/[\\*\\?]")
    r = s.to_regex("/")
    assert str(r.regexp) == "Test.*Special.\\(Plain\\)\\/\\[\\*\\?\\]"


def test_string_index(sigma_string):
    assert sigma_string[3] == SigmaString("s")


def test_string_index_negative(sigma_string):
    assert sigma_string[-1] == SigmaString("*")


def test_string_index_open_start(sigma_string):
    assert sigma_string[:3] == SigmaString("*Te")


def test_string_index_slice_without_escaped(sigma_string):
    assert sigma_string[3:9] == SigmaString("st*Str")


def test_string_index_slice_with_escaped(sigma_string):
    assert sigma_string[3:10] == SigmaString("st*Str\\*")


def test_string_index_slice_start_and_end_in_same_string_part(sigma_string):
    assert sigma_string[2:4] == SigmaString("es")


def test_string_index_slice_cut_out_escaped_wildcard(sigma_string):
    """The escaped wildcard at index 9 is a plain character and must not become special when cut out by a slice."""
    assert sigma_string[9:11] == SigmaString("\\*i")


def test_string_index_slice_cut_out_only_escaped_wildcard():
    s = SigmaString("a\\*b")
    assert s[1:2] == SigmaString("\\*")


def test_string_index_slice_cut_out_escaped_wildcard_cased():
    s = SigmaCasedString("a\\*b")
    assert type(s[1:2]) is SigmaCasedString
    assert s[1:2] == SigmaCasedString("\\*")


def test_string_index_slice_negative_end(sigma_string):
    assert sigma_string[3:-1] == SigmaString("st*Str\\*ing")


def test_string_index_slice_cut_first_and_last(sigma_string):
    assert sigma_string[1:-1] == SigmaString("Test*Str\\*ing")


def test_empty_string_index_slice_cut_first_and_last(empty_sigma_string):
    assert empty_sigma_string[1:-1] == SigmaString("")


def test_string_index_slice_negative_start_and_end(sigma_string):
    assert sigma_string[-3:-1] == SigmaString("ng")


def test_string_index_slice_open_end_with_escaped(sigma_string):
    assert sigma_string[9:] == SigmaString("\\*ing*")


def test_string_index_slice_open_end_without_escaped(sigma_string):
    assert sigma_string[10:] == SigmaString("ing*")


def test_string_index_slice_empty_result(sigma_string):
    assert sigma_string[4:2] == SigmaString("")


def test_string_index_slice_zero_stop(sigma_string):
    assert sigma_string[:0] == SigmaString("")
    assert sigma_string[0:0] == SigmaString("")
    assert sigma_string[1:0] == SigmaString("")
    assert sigma_string[1:1] == SigmaString("")
    assert sigma_string[-1:0] == SigmaString("")


def test_string_index_slice_start_after_end(sigma_string):
    assert sigma_string[100:] == SigmaString("")


def test_string_index_slice_open_start_negative_end(sigma_string):
    assert sigma_string[:-1] == SigmaString("*Test*Str\\*ing")


def test_string_index_cased_index():
    assert SigmaCasedString("TestCasedString")[4:9] == SigmaCasedString("Cased")


def test_string_index_cased_type():
    assert type(SigmaCasedString("TestCasedString")[4:9]) is SigmaCasedString


def test_string_index_invalid_type(sigma_string):
    with pytest.raises(TypeError, match="indices must be"):
        sigma_string["invalid"]


def test_string_index_slice_with_step(sigma_string):
    with pytest.raises(IndexError, match="slice index with step"):
        sigma_string[2:8:2]


def test_string_iter_parts(sigma_string):
    assert list(sigma_string.iter_parts()) == [
        SpecialChars.WILDCARD_MULTI,
        "Test",
        SpecialChars.WILDCARD_MULTI,
        "Str*ing",
        SpecialChars.WILDCARD_MULTI,
    ]


def test_string_map_parts(sigma_string):
    assert sigma_string.map_parts(lambda x: x.upper(), lambda x: isinstance(x, str)).s == [
        SpecialChars.WILDCARD_MULTI,
        "TEST",
        SpecialChars.WILDCARD_MULTI,
        "STR*ING",
        SpecialChars.WILDCARD_MULTI,
    ]


def test_string_map_parts_interpret_special(sigma_string):
    assert sigma_string.map_parts(lambda x: x.upper(), lambda x: isinstance(x, str), True).s == [
        SpecialChars.WILDCARD_MULTI,
        "TEST",
        SpecialChars.WILDCARD_MULTI,
        "STR",
        SpecialChars.WILDCARD_MULTI,
        "ING",
        SpecialChars.WILDCARD_MULTI,
    ]


def test_cased_string(sigma_string):
    assert SigmaCasedString.from_sigma_string(sigma_string) == SigmaCasedString("*Test*Str\\*ing*")


def test_number_int():
    assert SigmaNumber(123).number == 123


def test_number_float():
    assert SigmaNumber(12.34).number == 12.34


def test_number_to_plain():
    assert SigmaNumber(123).to_plain() == 123


def test_number_equal():
    assert SigmaNumber(123) == SigmaNumber(123)


def test_number_not_equal():
    assert SigmaNumber(123) != SigmaNumber(456)


def test_number_equal_plain():
    assert SigmaNumber(123) == 123


def test_number_not_equal_plain():
    assert SigmaNumber(123) != 456


def test_number_equal_wrong_type():
    with pytest.raises(NotImplementedError, match="SigmaNumber can only be compared"):
        SigmaNumber(123) == "123"


def test_number_invalid():
    with pytest.raises(SigmaValueError):
        SigmaNumber("test")


def test_number_invalid_non_finite():
    for value in [float("inf"), float("-inf"), float("nan")]:
        with pytest.raises(SigmaValueError, match="Invalid number"):
            SigmaNumber(value)


def test_field_reference():
    assert SigmaFieldReference("field").field == "field"


def test_re():
    assert SigmaRegularExpression("test.*")


def test_re_flags():
    r = SigmaRegularExpression("test.*", {flag for flag in SigmaRegularExpressionFlag})
    assert len(r.flags) == len(SigmaRegularExpressionFlag)


def test_re_add_flags():
    r = SigmaRegularExpression("test.*")
    r.add_flag(SigmaRegularExpressionFlag.IGNORECASE)
    assert r.flags == {SigmaRegularExpressionFlag.IGNORECASE}


def test_re_to_plain():
    assert SigmaRegularExpression("test.*").to_plain() == "test.*"


def test_re_to_plain_trailing_backslash():
    assert SigmaRegularExpression("test\\\\").to_plain() == "test\\\\"


def test_re_invalid():
    with pytest.raises(SigmaRegularExpressionError):
        SigmaRegularExpression("(test.*")


def test_re_escape():
    assert (
        SigmaRegularExpression("foo\\d+bar-test").escape(("foo", "-", "t"), "\\")
        == "\\foo\\\\d+bar\\-\\tes\\t"
    )


def test_re_escape_without_escape():
    assert (
        SigmaRegularExpression("foo\\d+bar-test").escape(("foo", "-", "t"), "\\", False)
        == "\\foo\\d+bar\\-\\tes\\t"
    )


def test_re_escape_with_escape_escape_char_param():
    # See issue #153 https://github.com/SigmaHQ/pySigma/issues/153
    assert (
        SigmaRegularExpression("bitsadmin\\.exe").escape(escape_escape_char=True)
        == "bitsadmin\\\\.exe"
    )
    assert (
        SigmaRegularExpression("bitsadmin\\.exe").escape(escape_escape_char=False)
        == "bitsadmin\\.exe"
    )


def test_bool():
    assert SigmaBool(True).boolean == True


def test_bool_true_cond():
    b = SigmaBool(True)
    if b:
        assert True
    else:
        assert False


def test_bool_false_cond():
    b = SigmaBool(False)
    if b:
        assert False
    else:
        assert True


def test_bool_str():
    assert str(SigmaBool(True)) == "True"


def test_bool_to_plain():
    assert SigmaBool(True).to_plain() == True


def test_bool_invalid():
    with pytest.raises(SigmaTypeError, match="must be a boolean"):
        SigmaBool(123)


def test_bool_equal():
    assert SigmaBool(True) == SigmaBool(True)


def test_bool_not_equal():
    assert SigmaBool(True) != SigmaBool(False)


def test_bool_equal_plain():
    assert SigmaBool(True) == True


def test_bool_not_equal_plain():
    assert SigmaBool(True) != False


def test_bool_equal_wrong_type():
    with pytest.raises(NotImplementedError, match="SigmaBool can only be compared"):
        SigmaBool(True) == "True"


def test_null_to_plain():
    assert SigmaNull().to_plain() == None


def test_null_equality():
    assert SigmaNull() == SigmaNull("foo")


def test_null_inequality():
    assert SigmaNull() != SigmaString("foo")


def test_conversion_str():
    assert sigma_type("Test") == SigmaString("Test")


def test_conversion_int():
    assert sigma_type(123) == SigmaNumber(123)


def test_conversion_float():
    assert sigma_type(12.34) == SigmaNumber(12.34)


def test_conversion_bool():
    assert sigma_type(True) == SigmaBool(True)


def test_conversion_none():
    assert sigma_type(None) == SigmaNull()


def test_conversion_unsupported():
    with pytest.raises(SigmaTypeError, match="Unsupported type"):
        sigma_type(object())


def test_query_expression():
    assert str(SigmaQueryExpression("test\\test*test?test[]", "id")) == "test\\test*test?test[]"


def test_query_expression_finalize():
    assert SigmaQueryExpression("{field} in list({id})", "id").finalize("xxx") == "xxx in list(id)"


def test_query_expression_finalize_nofield_error():
    with pytest.raises(SigmaValueError, match="no field was given"):
        SigmaQueryExpression("{field} in list({id})", "id").finalize()


def test_query_expression_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaQueryExpression("test", "id").to_plain()


def test_query_expression_wrong_expr_type():
    with pytest.raises(SigmaTypeError, match="must be a string"):
        SigmaQueryExpression(123, "id")


def test_query_expression_wrong_id_type():
    with pytest.raises(SigmaTypeError, match="must be a string"):
        SigmaQueryExpression("123", 123)


def test_cidr_ipv4():
    cidr_spec = "192.168.1.0/24"
    assert SigmaCIDRExpression(cidr_spec).network == IPv4Network(cidr_spec)


def test_cidr_ipv6():
    cidr_spec = "::1/128"
    assert SigmaCIDRExpression(cidr_spec).network == IPv6Network(cidr_spec)


def test_cidr_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaCIDRExpression("192.168.1.0/24").to_plain()


def test_cidr_to_str():
    assert str(SigmaCIDRExpression("192.168.1.0/24")) == "192.168.1.0/24"


def test_cidr_invalid():
    with pytest.raises(SigmaTypeError, match="Invalid CIDR expression"):
        SigmaCIDRExpression("1/132")


def test_cidr_expand_ipv4_0():
    assert SigmaCIDRExpression("0.0.0.0/0").expand() == ["*"]


def test_cidr_expand_ipv4_7():
    assert SigmaCIDRExpression("10.0.0.0/7").expand() == ["10.*", "11.*"]


def test_cidr_expand_ipv4_8():
    assert SigmaCIDRExpression("192.0.0.0/8").expand() == ["192.*"]


def test_cidr_expand_ipv4_14():
    assert SigmaCIDRExpression("192.168.0.0/14").expand() == [
        "192.168.*",
        "192.169.*",
        "192.170.*",
        "192.171.*",
    ]


def test_cidr_expand_ipv4_23():
    assert SigmaCIDRExpression("192.168.0.0/23").expand() == [
        "192.168.0.*",
        "192.168.1.*",
    ]


def test_cidr_expand_ipv4_24():
    assert SigmaCIDRExpression("192.168.1.0/24").expand() == ["192.168.1.*"]


def test_cidr_expand_ipv4_31():
    assert SigmaCIDRExpression("192.168.1.0/31").expand() == [
        "192.168.1.0",
        "192.168.1.1",
    ]


def test_cidr_expand_ipv4_32():
    assert SigmaCIDRExpression("192.168.1.1/32").expand() == ["192.168.1.1"]


def test_cidr_expand_ipv6_0():
    assert SigmaCIDRExpression("::/0").expand() == ["*"]


def test_cidr_expand_ipv4_budget_exceeded():
    """A /9 requires 128 byte-aligned patterns, which exceeds the default budget."""
    with pytest.raises(SigmaCIDRExpansionError, match="128 patterns"):
        SigmaCIDRExpression("10.0.0.0/9").expand()


def test_cidr_expand_ipv4_budget_configurable():
    patterns = SigmaCIDRExpression("10.0.0.0/9").expand(max_patterns=128)
    assert len(patterns) == 128
    assert patterns[0] == "10.0.*"
    assert patterns[-1] == "10.127.*"


def test_cidr_expand_no_truncation():
    """Expansion never returns a truncated result: exceeding the budget is an error."""
    with pytest.raises(SigmaCIDRExpansionError):
        SigmaCIDRExpression("0.0.0.0/1").expand(max_patterns=64)


def test_cidr_expand_ipv6_56_budget_exceeded():
    """A /56 requires 256 group-aligned patterns, which exceeds the default budget."""
    with pytest.raises(SigmaCIDRExpansionError, match="256 patterns"):
        SigmaCIDRExpression("1234:5678:0:ab00::/56").expand()


def test_cidr_expand_ipv6_56_budget_configurable():
    patterns = SigmaCIDRExpression("1234:5678:0:ab00::/56").expand(max_patterns=256)
    assert patterns == [f"1234:5678:0:ab{group:02x}:*" for group in range(0x100)]


def test_cidr_expand_ipv6_stops_before_generating_huge_networks():
    """The required pattern count is determined arithmetically before any pattern is generated."""
    with pytest.raises(SigmaCIDRExpansionError, match="32768"):
        SigmaCIDRExpression("2001:8000::/17").expand(max_patterns=1000)


def test_cidr_expand_ipv6_64_compressed():
    """Addresses of the network are compressed at the network prefix or in the host part."""
    assert SigmaCIDRExpression("2001:db8::/64").expand() == ["2001:db8:0:0:*", "2001:db8::*"]


def test_cidr_expand_ipv6_64_single_trailing_zero_group():
    assert SigmaCIDRExpression("2001:db8:1:0::/64").expand() == [
        "2001:db8:1:0:*",
        "2001:db8:1::*",
    ]


def test_cidr_expand_ipv6_16():
    assert SigmaCIDRExpression("::/16").expand() == ["0:*", "::*"]


def test_cidr_expand_ipv6_112_not_exact():
    """More than two trailing zero groups can't be matched exactly: :: compresses >= 2 groups."""
    with pytest.raises(SigmaCIDRExpansionError, match="more than two zero groups"):
        SigmaCIDRExpression("2001:db8::/112").expand()


def test_cidr_expand_ipv6_inner_zero_groups_not_exact():
    """Zero group sequences within the prefix are compressed depending on the host part."""
    with pytest.raises(SigmaCIDRExpansionError, match="consecutive zero groups"):
        SigmaCIDRExpression("2001:0:0:1::/64").expand()


def test_cidr_expand_ipv6_120_budget_exceeded():
    with pytest.raises(SigmaCIDRExpansionError, match="256 patterns"):
        SigmaCIDRExpression("2001:db8::/120").expand()


def test_cidr_expand_ipv6_128_compressed():
    assert SigmaCIDRExpression("2001:db8::1/128").expand() == [
        "2001:db8::1",
        "2001:db8:0:0:0:0:0:1",
    ]


def test_cidr_expand_ipv6_128_not_compressed():
    assert SigmaCIDRExpression("2001:db8:1:2:3:4:5:6/128").expand() == ["2001:db8:1:2:3:4:5:6"]


def test_cidr_expand_ipv6_10():
    """Non-group-aligned prefixes are expanded into group-aligned subnetworks."""
    assert SigmaCIDRExpression("fe80::/10").expand() == [
        f"fe{group:02x}:*" for group in range(0x80, 0xC0)
    ]


def test_cidr_expand_ipv6_128_ipv4_mapped_uncompressed():
    """Current Python versions write the last groups of IPv4-mapped addresses as dotted quad."""
    assert "0:0:0:0:0:ffff:102:304" in SigmaCIDRExpression("::ffff:102:304/128").expand()


def _uncompressed(address):
    """Uncompressed representation, as written by Sysmon: 0:0:0:0:0:0:0:1 for ::1"""
    digits = format(int(address), "032x")
    return ":".join(format(int(digits[i : i + 4], 16), "x") for i in range(0, 32, 4))


def _expansion_boundary_addresses(network):
    """
    Independent criterion built with the ipaddress module: addresses just inside and outside
    of the network boundaries, addresses with a single bit set or cleared at every host
    position (covers all zero group run positions and therefore all '::' compression
    variants) and addresses with one prefix bit flipped (guaranteed to be outside).
    """
    first = int(network.network_address)
    last = int(network.broadcast_address)
    host_bits = network.max_prefixlen - network.prefixlen
    inside = {first, last}
    for bit in range(host_bits):
        inside.add(first | (1 << bit))
        inside.add(last & ~(1 << bit))
    outside = set()
    if first > 0:
        outside.add(first - 1)
    if last < 2**network.max_prefixlen - 1:
        outside.add(last + 1)
    for bit in range(host_bits, network.max_prefixlen):
        outside.add(first ^ (1 << bit))
    address_class = IPv4Address if network.version == 4 else IPv6Address
    return (
        [address_class(value) for value in inside],
        [address_class(value) for value in outside],
    )


@pytest.mark.parametrize(
    "cidr",
    [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "192.0.0.0/8",
        "192.168.0.0/14",
        "192.168.0.0/23",
        "192.168.1.0/24",
        "192.168.1.0/31",
        "192.168.1.1/32",
        "::/0",
        "::/16",
        "::/32",
        "2001:db8::/64",
        "2001:db8:1:0::/64",
        "1234:5678:0:ab00::/58",
        "1234:5678:0:ab00::/64",
        "fe80::/10",
        "::1/128",
        "2001:db8::1/128",
        "2001:db8:1:2:3:4:5:6/128",
        "::ffff:102:304/128",
    ],
)
def test_cidr_expand_exact(cidr):
    """
    Proof with independent ipaddress-based criteria: the expanded patterns match the textual
    representations of all sampled addresses inside the network (no false negatives) and
    reject all sampled addresses outside of it (no widening of the network range). For IPv6
    both the RFC 5952 and the uncompressed representation are checked.
    """
    expression = SigmaCIDRExpression(cidr)
    patterns = expression.expand()
    network = expression.network
    inside, outside = _expansion_boundary_addresses(network)
    for address in inside:
        assert address in network
        texts = (
            [str(address)] if network.version == 4 else [str(address), _uncompressed(address)]
        )
        for text in texts:
            assert any(fnmatchcase(text, pattern) for pattern in patterns), text
    for address in outside:
        assert address not in network
        texts = (
            [str(address)] if network.version == 4 else [str(address), _uncompressed(address)]
        )
        for text in texts:
            assert not any(fnmatchcase(text, pattern) for pattern in patterns), text



def test_cidr_expand_ipv6_without_wildcard():
    assert SigmaCIDRExpression("2001:db8::/64").expand(wildcard=None) == ["2001:db8::/64"]


def test_cidr_expand_ipv4_without_wildcard():
    assert SigmaCIDRExpression("192.168.1.0/24").expand(wildcard=None) == ["192.168.1.0/24"]


def test_cidr_expand_ipv6_58():
    assert SigmaCIDRExpression("1234:5678:0:ab00::/58").expand() == [
        f"1234:5678:0:ab{group:02x}:*" for group in range(0x40)
    ]


def test_cidr_expand_ipv6_60():
    assert SigmaCIDRExpression("1234:5678:0:ab00::/60").expand() == [
        f"1234:5678:0:ab0{group:x}:*" for group in range(0x10)
    ]


def test_cidr_expand_ipv6_64():
    assert SigmaCIDRExpression("1234:5678:0:ab00::/64").expand() == ["1234:5678:0:ab00:*"]


def test_cidr_expand_ipv6_128():
    assert SigmaCIDRExpression("::1/128").expand() == ["::1", "0:0:0:0:0:0:0:1"]


def test_cidr_invalid():
    with pytest.raises(SigmaTypeError, match="Invalid CIDR expression"):
        SigmaCIDRExpression("192.168.1.2/24")


def test_compare_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaCompareExpression(SigmaNumber(123), CompareOperators.LTE).to_plain()


def test_compare_string():
    with pytest.raises(SigmaTypeError, match="expects number"):
        SigmaCompareExpression(SigmaString("123"), CompareOperators.LTE).to_plain()
