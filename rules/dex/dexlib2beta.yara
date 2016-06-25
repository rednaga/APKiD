import "dex"

rule dexlib2beta
{
  meta:
    description = "Compiled with Dexlib 2.x Beta"
    author = "Caleb Fenton <calebjfenton@gmail.com>"
    last_modified = "2016-06-24"

  condition:
    /*
     * Dexlib2 adds a non-zero interfaces_off to every class_def_item, even if the class doesn't implement an
     * interface. It points to 4 null bytes right after string pool. DEX documentation says the value for
     * interfaces_off should be 0 if there is no interface, which is what DX does. It's enough to check
     * if a single class has an interface which points to null bytes since no one else does this.
     */
    for any i in (0..dex.header.class_defs_size) : (dex.class_defs[i].interfaces_off > 0 and uint32(dex.class_defs[i].interfaces_off) == 0)
}
