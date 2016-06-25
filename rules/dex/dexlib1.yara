import "dex"

rule dexlib1
{
  meta:
    description = "Compiled with Dexlib 1.x"
    author = "Caleb Fenton <calebjfenton@gmail.com>"
    last_modified = "2016-06-24"

  condition:
    /*
     * DEX format requires string IDs to be sorted according to the data at their offsets but the actual
     * ordering of the string pool is undefined. Dexlib (smali/apktool) 1.x sorts strings by class and
     * proximity. DX sorts strings in the same order as the string table.
     */  
    for any i in (0..dex.header.string_ids_size - 1) : (dex.string_ids[i].offset + dex.string_ids[i].item_size + 1 != dex.string_ids[i + 1].offset)
}
