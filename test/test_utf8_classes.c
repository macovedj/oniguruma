/* Search-time UTF-8 character-class validation, including byte offsets. */
#include <stdio.h>
#include <string.h>

#include "oniguruma.h"

#define VALID ONIG_OPTION_VALID_UTF8_CLASSES
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int nsucc;
static int nfail;
static int nerror;

static const OnigUChar bad_ff[]       = { 0xff };
static const OnigUChar bad_tail[]     = { 0x80 };
static const OnigUChar overlong2[]    = { 0xc0, 0xaf };
static const OnigUChar overlong3[]    = { 0xe0, 0x80, 0xaf };
static const OnigUChar surrogate[]    = { 0xed, 0xa0, 0x80 };
static const OnigUChar out_of_range[] = { 0xf4, 0x90, 0x80, 0x80 };
static const OnigUChar truncated[]    = { 0xe2, 0x82 };
static const OnigUChar mixed_ff[]     = { 'a', 0xff, 'b' };
static const OnigUChar mixed_bad[]    = { 'a', 0xe2, '(', 0xa1, 'b' };
static const OnigUChar mixed_space[]  = { 0xe2, ' ', 0xa1 };
static const OnigUChar mixed_nul[]    = { 'a', 0, 'b' };
static const OnigUChar longest[]      = { 'a', 0xff, 'b', 'b', 'b' };
static const OnigUChar scan_bytes[]   = { 0xc3, 0xa9, 0xff, 'b' };
static const OnigUChar empty[]        = { 0 };

static OnigRegex
compile(const char* name, const char* pattern, OnigOptionType options,
        OnigEncoding enc)
{
  int r;
  OnigRegex reg;
  OnigErrorInfo einfo;
  OnigUChar message[ONIG_MAX_ERROR_MESSAGE_LEN];

  r = onig_new(&reg, (const OnigUChar* )pattern,
               (const OnigUChar* )pattern + strlen(pattern), options,
               enc, ONIG_SYNTAX_ONIGURUMA, &einfo);
  if (r != ONIG_NORMAL) {
    onig_error_code_to_str(message, r, &einfo);
    fprintf(stderr, "ERROR: %s /%s/: %s\n", name, pattern, message);
    nerror++;
    return NULL;
  }
  return reg;
}

static void
expect_result(const char* name, const char* pattern, int result,
              OnigRegion* region, int expected_result, int from, int to)
{
  if (result != expected_result ||
      (result >= 0 && region != NULL &&
       (region->num_regs < 1 || region->beg[0] != from || region->end[0] != to))) {
    fprintf(stderr, "FAIL: %s /%s/: result %d, expected %d",
            name, pattern, result, expected_result);
    if (result >= 0 && region != NULL && region->num_regs > 0)
      fprintf(stderr, ", span %d-%d, expected %d-%d",
              region->beg[0], region->end[0], from, to);
    fputc('\n', stderr);
    nfail++;
  }
  else
    nsucc++;
}

static void
search(const char* name, const char* pattern,
       const OnigUChar* bytes, size_t len, size_t start, size_t range,
       OnigOptionType compile_options, OnigOptionType search_options,
       int from, int to, int with_region)
{
  int r;
  OnigRegion* region;
  OnigRegex reg = compile(name, pattern, compile_options, ONIG_ENCODING_UTF8);
  if (reg == NULL) return;
  region = with_region ? onig_region_new() : NULL;
  r = onig_search(reg, bytes, bytes + len, bytes + start, bytes + range,
                  region, search_options);
  expect_result(name, pattern, r, region, from, from, to);
  if (region != NULL) onig_region_free(region, 1);
  onig_free(reg);
}

static void
match(const char* name, const char* pattern,
      const OnigUChar* bytes, size_t len, size_t at,
      OnigOptionType compile_options, OnigOptionType search_options,
      int from, int to, int with_region)
{
  int r;
  OnigRegion* region;
  OnigRegex reg = compile(name, pattern, compile_options, ONIG_ENCODING_UTF8);
  if (reg == NULL) return;
  region = with_region ? onig_region_new() : NULL;
  r = onig_match(reg, bytes, bytes + len, bytes + at, region, search_options);
  expect_result(name, pattern, r, region, from < 0 ? from : to - from, from, to);
  if (region != NULL) onig_region_free(region, 1);
  onig_free(reg);
}

static void
anchored_longest(void)
{
  int r;
  OnigRegion* region;
  const char* name = "anchored longest does not skip invalid byte";
  const char* pattern = "\\S+";
  OnigRegex reg = compile(name, pattern, ONIG_OPTION_FIND_LONGEST,
                          ONIG_ENCODING_UTF8);
  if (reg == NULL) return;
  region = onig_region_new();
  r = onig_match(reg, longest, longest + sizeof(longest), longest, region, VALID);
  /* For this pattern with compiled FIND_LONGEST, onig_match retains the
     longest capture but returns ONIG_MISMATCH after exhausting alternatives.
     Check both facts independently rather than treating an arbitrary failure
     as a match. */
  expect_result(name, pattern, r, NULL, ONIG_MISMATCH, 0, 0);
  if (region->num_regs < 1 || region->beg[0] != 0 || region->end[0] != 1) {
    fprintf(stderr, "FAIL: %s: expected retained span 0-1\n", name);
    nfail++;
  }
  else
    nsucc++;
  onig_region_free(region, 1);
  onig_free(reg);
}

#define SEARCH(name, p, s, f, t) \
  search(name, p, s, sizeof(s), 0, sizeof(s), \
         ONIG_OPTION_NONE, VALID, f, t, 1)
#define MATCH(name, p, s, at, f, t) \
  match(name, p, s, sizeof(s), at, ONIG_OPTION_NONE, VALID, f, t, 1)

static void
malformed_classes(void)
{
  static const struct {
    const char* name;
    const OnigUChar* bytes;
    size_t len;
  } cases[] = {
    { "invalid lead byte", bad_ff, sizeof(bad_ff) },
    { "stray continuation", bad_tail, sizeof(bad_tail) },
    { "two-byte overlong", overlong2, sizeof(overlong2) },
    { "three-byte overlong", overlong3, sizeof(overlong3) },
    { "surrogate", surrogate, sizeof(surrogate) },
    { "above Unicode maximum", out_of_range, sizeof(out_of_range) },
    { "truncated character", truncated, sizeof(truncated) }
  };
  static const char* patterns[] = {
    "\\S", "\\s", "[[:space:]]", "[[:^space:]]", "[^[:space:]]",
    "[\\x{0}-\\x{10ffff}]"
  };
  size_t i, j;

  for (i = 0; i < ARRAY_SIZE(cases); i++) {
    for (j = 0; j < ARRAY_SIZE(patterns); j++) {
      search(cases[i].name, patterns[j], cases[i].bytes, cases[i].len,
             0, cases[i].len, ONIG_OPTION_NONE, VALID, ONIG_MISMATCH, 0, 1);
    }
  }

  /* Representative positive, negative and multibyte-only classes. */
  SEARCH("positive digit class", "\\d", overlong2, ONIG_MISMATCH, 0);
  SEARCH("negative digit class", "\\D", overlong2, ONIG_MISMATCH, 0);
  SEARCH("negative Unicode property", "\\P{L}", overlong2, ONIG_MISMATCH, 0);
  SEARCH("positive multibyte class", "[\\x{80}-\\x{10ffff}]",
         surrogate, ONIG_MISMATCH, 0);
  SEARCH("mixed single/multibyte class", "[a\\x{80}-\\x{10ffff}]",
         surrogate, ONIG_MISMATCH, 0);
}

static void
valid_characters(void)
{
  static const OnigUChar boundaries[][4] = {
    { 0 }, { 0x7f }, { 0xc2, 0x80 }, { 0xdf, 0xbf },
    { 0xe0, 0xa0, 0x80 }, { 0xed, 0x9f, 0xbf }, { 0xee, 0x80, 0x80 },
    { 0xef, 0xbf, 0xbf }, { 0xf0, 0x90, 0x80, 0x80 },
    { 0xf4, 0x8f, 0xbf, 0xbf }
  };
  static const size_t lengths[] = { 1, 1, 2, 2, 3, 3, 3, 3, 4, 4 };
  static const OnigUChar em_space[] = { 0xe2, 0x80, 0x83 };
  static const OnigUChar smile[] = { 0xf0, 0x9f, 0x98, 0x80 };
  static const OnigUChar ascii_space[] = { ' ' };
  static const OnigUChar digit[] = { '7' };
  static const OnigUChar folded[] = { 0xce, 0xb9, 0xcc, 0x88, 0xcc, 0x81 };
  static const OnigUChar overlong_iota[] = {
    0xe0, 0x8e, 0xb9, 0xcc, 0x88, 0xcc, 0x81
  };
  static const OnigUChar overlong_diaeresis[] = {
    0xce, 0xb9, 0xe0, 0x8c, 0x88, 0xcc, 0x81
  };
  size_t i;

  for (i = 0; i < ARRAY_SIZE(boundaries); i++) {
    search("valid UTF-8 boundary", "[\\x{0}-\\x{10ffff}]",
           boundaries[i], lengths[i], 0, lengths[i], ONIG_OPTION_NONE,
           VALID, 0, (int )lengths[i], 1);
  }
  SEARCH("ASCII whitespace", "\\s", ascii_space, 0, 1);
  SEARCH("Unicode whitespace", "\\s", em_space, 0, 3);
  SEARCH("Unicode positive class", "[[:space:]]", em_space, 0, 3);
  SEARCH("Unicode whitespace is not nonspace", "\\S", em_space, ONIG_MISMATCH, 0);
  SEARCH("valid four-byte nonspace", "\\S", smile, 0, 4);
  SEARCH("positive ASCII class", "[0-9]", digit, 0, 1);
  SEARCH("embedded NUL is a valid character", "\\S+", mixed_nul, 0, 3);

  /* A class can expand into multiple characters under Unicode case folding. */
  search("valid multi-character fold", "[\xce\x90]", folded, sizeof(folded),
         0, sizeof(folded), ONIG_OPTION_IGNORECASE, VALID, 0, 6, 1);
  search("overlong first folded character", "[\xce\x90]", overlong_iota,
         sizeof(overlong_iota), 0, sizeof(overlong_iota),
         ONIG_OPTION_IGNORECASE, VALID, ONIG_MISMATCH, 0, 1);
  search("overlong combining folded character", "[\xce\x90]", overlong_diaeresis,
         sizeof(overlong_diaeresis), 0, sizeof(overlong_diaeresis),
         ONIG_OPTION_IGNORECASE, VALID, ONIG_MISMATCH, 0, 1);
}

static void
search_and_match(void)
{
  static const OnigUChar padded[] = { 'a', 'b', 0, 0 };

  SEARCH("valid prefix", "\\S+", mixed_ff, 0, 1);
  search("valid suffix", "\\S+", mixed_ff, sizeof(mixed_ff), 1,
         sizeof(mixed_ff), ONIG_OPTION_NONE, VALID, 2, 3, 1);
  search("ASCII inside malformed sequence", "\\S", mixed_bad, sizeof(mixed_bad),
         1, sizeof(mixed_bad), ONIG_OPTION_NONE, VALID, 2, 3, 1);
  search("quantified ASCII inside malformed sequence", "\\S+",
         mixed_bad, sizeof(mixed_bad), 1, sizeof(mixed_bad),
         ONIG_OPTION_NONE, VALID, 2, 3, 1);
  SEARCH("valid space inside malformed sequence", "\\s", mixed_space, 1, 2);
  SEARCH("backtracking before invalid byte", "\\S*b", mixed_ff, 2, 3);
  SEARCH("alternation after invalid byte", "\\S+z|b", mixed_ff, 2, 3);
  SEARCH("whole-line class rejects invalid byte", "^\\S+$",
         mixed_ff, ONIG_MISMATCH, 0);
  SEARCH("invalid bytes do not create beginning", "^b", mixed_ff, ONIG_MISMATCH, 0);
  SEARCH("invalid bytes do not create ending", "a$", mixed_ff, ONIG_MISMATCH, 0);

  MATCH("anchored valid prefix", "\\S+", mixed_ff, 0, 0, 1);
  MATCH("anchored invalid character", "\\S", mixed_ff, 1, ONIG_MISMATCH, 0);
  MATCH("anchored valid suffix", "\\S", mixed_ff, 2, 2, 3);
  MATCH("anchored malformed character", "\\S", mixed_bad, 1, ONIG_MISMATCH, 0);
  MATCH("anchored recovered ASCII", "\\S", mixed_bad, 2, 2, 3);
  search("boolean rejects overlong character", "\\S", overlong2,
         sizeof(overlong2), 0, sizeof(overlong2), ONIG_OPTION_NONE,
         VALID, ONIG_MISMATCH, 0, 0);
  search("boolean finds recovered ASCII", "\\S", mixed_bad,
         sizeof(mixed_bad), 1, sizeof(mixed_bad), ONIG_OPTION_NONE, VALID, 2, 3, 0);
  match("boolean anchored rejection", "\\S", overlong2, sizeof(overlong2),
        0, ONIG_OPTION_NONE, VALID, ONIG_MISMATCH, 0, 0);

  search("global longest valid match", "\\S+", longest, sizeof(longest),
         0, sizeof(longest), ONIG_OPTION_FIND_LONGEST, VALID, 2, 5, 1);
  anchored_longest();

  search("equal range checks one candidate", "\\S+", mixed_ff,
         sizeof(mixed_ff), 0, 0, ONIG_OPTION_NONE, VALID, 0, 1, 1);
  search("equal range does not search ahead", "\\S", mixed_ff,
         sizeof(mixed_ff), 1, 1, ONIG_OPTION_NONE, VALID, ONIG_MISMATCH, 0, 1);
  search("empty match at end", "", mixed_ff, sizeof(mixed_ff),
         sizeof(mixed_ff), sizeof(mixed_ff), ONIG_OPTION_NONE, VALID, 3, 3, 1);
  search("empty input", "", empty, 0, 0, 0, ONIG_OPTION_NONE, VALID, 0, 0, 1);
  search("class on empty input", "\\S", empty, 0, 0, 0,
         ONIG_OPTION_NONE, VALID, ONIG_MISMATCH, 0, 1);
  search("forward range bounds consumption", "\\S+", padded, 2, 0, 1,
         ONIG_OPTION_NONE, VALID, 0, 1, 1);
  search("range beyond end rejected", "\\S", padded, 2, 0, 3,
         ONIG_OPTION_NONE, VALID, ONIGERR_INVALID_ARGUMENT, 0, 1);
  search("backward search rejected", "\\S", mixed_ff, sizeof(mixed_ff),
         2, 0, ONIG_OPTION_NONE, VALID, ONIGERR_INVALID_ARGUMENT, 0, 1);

  /* Opting in must not silently change callers that leave the flag off. */
  search("legacy nonspace accepts FF", "\\S", bad_ff, sizeof(bad_ff),
         0, sizeof(bad_ff), ONIG_OPTION_NONE, ONIG_OPTION_NONE, 0, 1, 1);
  search("legacy inner negation rejects FF", "[[:^space:]]", bad_ff,
         sizeof(bad_ff), 0, sizeof(bad_ff), ONIG_OPTION_NONE,
         ONIG_OPTION_NONE, ONIG_MISMATCH, 0, 1);
  search("legacy invalid byte match", "\\S", overlong2,
         sizeof(overlong2), 0, sizeof(overlong2), ONIG_OPTION_NONE,
         ONIG_OPTION_NONE, 0, 1, 1);
}

struct scan_expectation {
  const char* name;
  const int* starts;
  const int* ends;
  int count;
  int seen;
};

static int
scan_callback(int n, int result, OnigRegion* region, void* arg)
{
  struct scan_expectation* expected = (struct scan_expectation* )arg;
  if (n >= expected->count) {
    fprintf(stderr, "FAIL: %s: unexpected scan callback %d\n", expected->name, n);
    nfail++;
    return -1;
  }
  expected->seen++;
  expect_result(expected->name, "scan", result, region,
                expected->starts[n], expected->starts[n], expected->ends[n]);
  return 0;
}

static void
scan(const char* name, const char* pattern, const OnigUChar* bytes, size_t len,
     const int* starts, const int* ends, int count)
{
  int r;
  struct scan_expectation expected;
  OnigRegion* region;
  OnigRegex reg = compile(name, pattern, ONIG_OPTION_NONE, ONIG_ENCODING_UTF8);
  if (reg == NULL) return;
  expected.name = name;
  expected.starts = starts;
  expected.ends = ends;
  expected.count = count;
  expected.seen = 0;
  region = onig_region_new();
  r = onig_scan(reg, bytes, bytes + len, region, VALID, scan_callback, &expected);
  if (r != count || expected.seen != count) {
    fprintf(stderr, "FAIL: %s: scan result %d, callbacks %d, expected %d\n",
            name, r, expected.seen, count);
    nfail++;
  }
  else
    nsucc++;
  onig_region_free(region, 1);
  onig_free(reg);
}

static void
scan_cases(void)
{
  static const int empty_positions[] = { 0, 2, 3, 4 };
  static const int nonspace_starts[] = { 0, 3 };
  static const int nonspace_ends[] = { 2, 4 };
  static const int empty_position[] = { 0 };
  scan("empty scan recovers safely", "", scan_bytes, sizeof(scan_bytes),
       empty_positions, empty_positions, 4);
  scan("class scan preserves offsets", "\\S+", scan_bytes, sizeof(scan_bytes),
       nonspace_starts, nonspace_ends, 2);
  scan("empty scan at empty input", "", empty, 0,
       empty_position, empty_position, 1);
}

static void
unsupported_apis(void)
{
  int r;
  int position;
  OnigRegex reg;
  OnigRegex regs[1];
  OnigRegSet* set;
  OnigErrorInfo einfo;
  OnigRegion* region;
  const OnigUChar pattern[] = { '\\', 'S' };

  r = onig_new(&reg, pattern, pattern + sizeof(pattern), VALID,
               ONIG_ENCODING_UTF8, ONIG_SYNTAX_ONIGURUMA, &einfo);
  expect_result("runtime-only option", "\\S", r, NULL,
                ONIGERR_INVALID_ARGUMENT, 0, 0);
  if (r == ONIG_NORMAL) onig_free(reg);

  reg = compile("non-UTF8 encoding", "\\S", ONIG_OPTION_NONE,
                 ONIG_ENCODING_ISO_8859_1);
  if (reg != NULL) {
    region = onig_region_new();
    r = onig_search(reg, bad_ff, bad_ff + sizeof(bad_ff), bad_ff,
                    bad_ff + sizeof(bad_ff), region, VALID);
    expect_result("non-UTF8 search rejected", "\\S", r, region,
                  ONIGERR_INVALID_ARGUMENT, 0, 0);
    r = onig_match(reg, bad_ff, bad_ff + sizeof(bad_ff), bad_ff, region, VALID);
    expect_result("non-UTF8 match rejected", "\\S", r, region,
                  ONIGERR_INVALID_ARGUMENT, 0, 0);
    onig_region_free(region, 1);
    onig_free(reg);
  }

  regs[0] = compile("regset", "\\S", ONIG_OPTION_NONE, ONIG_ENCODING_UTF8);
  if (regs[0] == NULL) return;
  r = onig_regset_new(&set, 1, regs);
  if (r != ONIG_NORMAL) {
    fprintf(stderr, "ERROR: creating regset: %d\n", r);
    nerror++;
    onig_free(regs[0]);
    return;
  }
  r = onig_regset_search(set, mixed_ff, mixed_ff + sizeof(mixed_ff), mixed_ff,
                         mixed_ff + sizeof(mixed_ff), ONIG_REGSET_POSITION_LEAD,
                         VALID, &position);
  expect_result("regset search rejected", "\\S", r, NULL,
                ONIGERR_INVALID_ARGUMENT, 0, 0);
  onig_regset_free(set);
}

int
main(void)
{
  OnigEncoding encodings[] = { ONIG_ENCODING_UTF8, ONIG_ENCODING_ISO_8859_1 };
  int r = onig_initialize(encodings, (int )ARRAY_SIZE(encodings));
  if (r != ONIG_NORMAL) {
    fprintf(stderr, "ERROR: initialization: %d\n", r);
    return 1;
  }
  malformed_classes();
  valid_characters();
  search_and_match();
  scan_cases();
  unsupported_apis();
  fprintf(stdout, "RESULT UTF8_CLASSES SUCC: %d, FAIL: %d, ERROR: %d\n",
          nsucc, nfail, nerror);
  onig_end();
  return nfail == 0 && nerror == 0 ? 0 : 1;
}
