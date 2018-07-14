import warnings

from apkid import rules


def test_rules_compile():
    rulez = rules.load()
    assert rulez


def test_lint_rules():
    for r in rules.load():
        if len(r.tags) == 0:
            warnings.warn("rule has no tags: {}".format(r.identifier), stacklevel=0)

        if 'description' not in r.meta:
            warnings.warn("rule has no tags: {}".format(r.identifier), stacklevel=0)

        if ('packer' in r.tags or 'protector' in r.tags or 'obfuscator' in r.tags) \
                and 'sample' not in r.meta:
            warnings.warn("rule has no reference sample: {}".format(r.identifier), stacklevel=0)
