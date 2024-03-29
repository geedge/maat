# Logical combinations

When you understand the [configuration relationship](./overview.md#12-configuration-relationship) and [group hierarchy](./group_hierarchy.md), you will find multiple layers of logical relationships. Are all these logical relationships necessary? If yes, what are the use cases targeted by each? This document serves as a cheat sheet for you to understand the logical combinations of maat rules.

Before describing specific rules, we need to define the syntax of logical combinations. A rule is written using infix notation, which consists of operands, operators, and parentheses. The operands are rule IDs, and operators are "!(NOT)", "&(AND)", "|(OR)".

Before showing how to configure the specific rules, we need some raw materials (items). The following is the configuration information for the different types of item tables:

**keywords(table_id=1)**
| item_id | group_id | keywords      |
| ------- | -------- | ------------- |
| 101     | 201      | www.baidu.com |
| 102     | 202      | baidu.com     | 

**ip address(table_id=2)**
| item_id | group_id | ip range                    |
| ------- | -------- | --------------------------- |
| 110     | 210      | 192.168.1.1 ~ 192.168.1.255 |
| 111     | 211      | 192.168.1.11 ~ 192.168.1.20 |
| 112     | 212      | 192.168.1.21 ~ 192.168.1.30 |

**port(table_id=3)**
| item_id | group_id | interval range |
| ------- | -------- | -------------- |
| 120     | 220      | 100 ~ 200      |
| 121     | 221      | 80 ~ 80        |
| 122     | 222      | 443 ~ 443      |

* [AND logic](#and-logic)
* [OR logic](#or-logic)
* [NOT logic](#not-logic)
* [Group exclude](#group-exclude)

## AND logic

`Note`: Each compile supports a maximum of 8 clauses, which are connected by the logical 'AND' relationship, with clause index ranging from 0 to 7.

* case1: Deny hosts with source IP addresses in the range of 192.168.1.11 to 192.168.1.20 from accessing the website www.baidu.com.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * www.baidu.com => group_id(201)

```bash
compile(rule) = clause1 & clause2
              = {vtable1, group1, clause_index1} & {vtable2, group2, clause_index2}
              = {2, 211, 1} & {1, 201, 2}
```

* case2: To block the traffic whose source IP address is 192.168.1.11 to 192.168.1.20 and source port 80.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * 端口80 ~ 80 => group_id(221)

```bash
compile(rule) = clause1 & clause2
              = {vtable1, group1, clause_index1} & {vtable2, group2, clause_index2}
              = {2, 211, 1} & {3, 221, 2}
```

The JSON configuration for the logical `AND` can be referenced at [unit_test Json configuration](../test/maat_json.json) with compile_id=152.

group_name: "152_mail_addr" and group_name: "interval_group_refered" are two clauses of this compile, with a logical `AND` relationship between them.


## OR logic

`Note`: Multiple groups under the same clause have a logical 'OR' relationship.

* case1： Deny hosts with source IP addresses in the range of 192.168.1.11 to 192.168.1.30 from accessing the website www.baidu.com.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * 192.168.1.21 ~ 192.168.1.30 => group_id(212)
    * www.baidu.com => group_id(201)

```bash
compile(rule) = clause1 & clause2
              = {vtable1, (group1 | group2), clause_index1} & {vtable2, group3, clause_index2}
              = {2, (211 | 212), 1} & {1, 201, 2}
```

* case2: To block the traffic whose source ip address is 192.168.1.11 to 192.168.1.20 and source port 80 or 443.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * port 80 ~ 80 => group_id(221)
    * port 443 ~ 443 => group_id(222)

```bash
compile(rule) = clause1 & clause2
              = {vtable1, group1, clause_index1} & {vtable2, (group2 | group3), clause_index2}
              = {2, 211, 1} & {3, (221 | 222), 2}
```

The JSON configuration for the logical `OR` can be referenced at [unit_test Json configuration](../test/maat_json.json) with compile_id=152.

group_name: "152_mail_addr" contains two regions(items) with a logical `OR` relationship between them.


## NOT logic

`Note`: Only clauses can support NOT-logic.

* case1: Hosts with source ip addresses ranging from 192.168.1.11 to 192.168.1.20 are allowed to access websites other than www.baidu.com.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * www.baidu.com => group_id(201)

```bash
compile(rule) = clause1 & !clause2
              = {vtable1, group1, clause_index1} & !{vtable2, group2, clause_index2}
              = {2, 211, 1} & !{1, 201, 2}
```

* case2: To block the traffic whose source ip address is in 192.168.1.11 to 192.168.1.20 and the source port is not 80 or 443.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * port 80 ~ 80 => group_id(221)
    * port 443 ~ 443 => group_id(222)

```bash
compile(rule) = clause1 & !clause2
              = {vtable1, group1, clause_index1} & !{vtable2, (group2 | group3), clause_index2}
              = {2, 211, 1} & !{3, (221 | 222), 2}
```

The JSON configuration for the logical `OR` can be referenced at [unit_test Json configuration](../test/maat_json.json) with compile_id=145.

The group_name: "123_IP_group" is a NOT clause of this compile.


## Group exclude

`Note`: The `exclude` relationship only applies between groups of the same type, such as super_group1 = include {group1}, exclude {group2}.

Constraint: The super group cannot consist only of exclude groups; it must contain at least one include group.

* case1: Deny hosts with source IP addresses in the range of 192.168.1.1 to 192.168.1.255 but not in the range of 192.168.1.11 to 192.168.1.20 from accessing the website www.baidu.com.

    * 192.168.1.1 ~ 192.168.1.255 => group_id(210)
    * 192.168.1.11 ~ 192.168.20 => group_id(211)
    * www.baidu.com => group_id(201)

In this case, you need to configure super_group1 first.
```bash
super_group1 = group1 exclude group2
             = 210 exclude 211
```

And then configure the compile.
```bash
compile(rule) = clause1 & clause2
              = {vtable1, super_group1, clause_index1} & {vtable2, group2, clause_index2}
              = {2, (210 exclude 211), 1} & {1, 201, 2}
```

* case2: Deny hosts with source IP addresses in the range of 192.168.1.11 to 192.168.1.20 from accessing subdomains of baidu.com except for www.baidu.com.

    * 192.168.1.11 ~ 192.168.1.20 => group_id(211)
    * www.baidu.com => group_id(201)
    * baidu.com => group_id(202)

In this case, you need to configure super_group2 first.
```bash
super_group2 = group2 exclude group3
             = 202 exclude 201
```

And then configure the compile.
```bash
compile(rule) = clause1 & clause2
              = {vtable1, group1, clause_index1} & {vtable2, super_group2, clause_index2}
              = {2, 211, 1} & {1, (202 exclude 201), 2}
```

The JSON configuration for the logical `OR` can be referenced at [unit_test Json configuration](../test/maat_json.json) with compile_id=200.

The group_name: "ExcludeLogicGroup200" is a super group that includes an include group "ExcludeLogicGroup200_1" and an exclude group "ExcludeLogicGroup200_2".