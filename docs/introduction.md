# Concepts

**Item**: As a filter for network attributes, the smallest unit of a rule

- Eg1: specify that the UserAgent field in the HTTP protocol contains substrings "Chrome" and "11.8.1",  
   &ensp;&ensp; HTTP UserAgent: Chrome & 11.8.1

- Eg2: specify that the domain name in the HTTP protocol ends with ".emodao.com"  
   &ensp;&ensp; HTTP HOST: *.emodao.com

- Eg3: specify client IP address belongs to the C segment of 202.118.101.*  
   &ensp;&ensp; Source IP: 202.11.101.0/24

There are multiple types of items stored in corresponding tables such as string, IP and numerical range, more details can be found in [Item table](./table_schema.md#item-table).

**Group(Object)**: Collection of Items, the constraints of group are as follows:

- An Item only belongs to one group, but one group can has multiple items. The multiple items under the same group are logical 'OR' relationships. e.g.(g1 = item1 | item2)

- A Group can be included or excluded by other groups. The multiple included groups under the same superior group are logical 'OR' relationship. e.g.(g3 = incl-g1 | incl-g2). Between included group and excluded group under the same superior group are logical 'AND' relationship. e.g.(g4 = incl-g1 & excl-g2)

- Group supports multi-level nesting

- A Group can be referenced by multiple compiles.

The relationship between group and group is stored in the [group2group table](./table_schema.md#4-group2group-table), while the relationship between group and compile is stored in the [group2compile table](./table_schema.md#5-group2compile-table).

**Compile(Policy)**: A conjunctive normal form(CNF) consisting of multiple groups and virtual tables

- A Compile can contain up to 8 clauses and multiple clauses in the same compile can be logical 'AND' and logical 'NOT' relationships.

- A Clause consists of several Literals and the relationship between them is a logical 'OR'. A Literal consists of virtual table and group. During the rules loading process, a unique Clause ID will be generated based on the combination of virtual table ID and group ID in the same clause.


![CNF](./imgs/CNF.jpg)

Rule Diagram
![Rule Diagram](./imgs/rule_diagram.png)

## Group/Object Nesting and Hierarchies

The objects and items are compared in the rule evaluation with **OR** operator. If a traffic attribute satisfies an item, the object it belongs to is satisfied.

### Exclude

An object defines a subset of an object type, such as network addresses or port numbers. The definition is made using items, which can be used to add to or exclude from the object definition. Objects can also have subordinate objects whose definitions are included in the superior object.

There are rules of precedence to take into account when defining objects:

- Excluding has precedence over including in the same object.

- Items in a superior object have precedence over items in a subordinate object.

- Items in a superior object are not taken into account in a subordinate object, if the subordinate object is used directly in a rule.

- Peer objects (different subordinate objects of the same superior object) do not affect each other.

In short, to determine the set defined by an object, perform the following calculation:

1. For each subordinate object (remember sibling objects do not affect each other):
   - Add included items.
   
   - Subtract excluded items.

2. Add included items in the object itself, overriding any excludes in the subordinate objects.

3. Subtract excluded items in the object itself.

The following figure shows an object with an included set and an excluded subset.

![exclude](./imgs/exclude.png)

Now, consider adding a subordinate object. The subordinate object also has an included set and an excluded subset. If the superior object is used, the result is shown in the following figure “A superior and subordinate object”.

![A superior and subordinate object](./imgs/hierarchy-and-exclude.png)

As can be seen, the excluded item in the subordinate object is overwritten since it is in the included set of the superior object. Also, the excluded item from the superior object excludes part of the included item in the subordinate.

If only the subordinate object is used in a rule condition, the superior object items are disregarded, leaving the set shown in the next figure, “The subordinate object”.

![The subordinate object](./imgs/sub-exclude.png)

Restrictions:

- An object can only include or exclude objects of the same type.
- An object should include at least one subordinate object. (Exclude only is not allowed)
- Traffic attribute using stream scan cannot allow use object with exclude, i.e., keywords object on HTTP Response Body, Email attachment.

Now, let's see a graph of hierarchy example, where the dotted line means exclude. The matched subordinate objects and activated superiors are listed in the following table.

![object-hierarchy-example](./imgs/object-hierarchy-example.png)


| **Matched subordinate objects** | **Activated superior Objects** |
| ------------------------------- | ------------------------------ |
| g1, g3                          | g6, g9                         |
| g3, g4                          | none                           |
| g5                              | g8, g10, g13                   |
| g2, g3                          | g9                             |
| g3, g5                          | none                           |
| g8, g11                         | g10, g12                       |
| g4, g11                         | g7, g8, g9                     |
| g1, g2                          | g9                             |

## Defined Terms

| **Term**                    | **Description**                                                      |
| --------------------------- | ------------------------------------------------------------ |
| Instance                    | Maat handle                                                  |
| Item                        | Rule of a certain field，such as URL field in HTTP protocol, client ip address field in DNS protocol etc.|
| Group(Object)               | A collection of one or more Items, the multiple items under the same Group are logical 'OR' relationships |
| Compile(Policy)             | A rule for several Groups logical AND or NOT operations   |
| Table                       | Different types of rules have different tables, such as ip table, keywords table, group2compile table, compile table etc.  |
| Physical Table              | The actual table in the database |
| Virtual Table               | Table that do not exist in the database and only references physical table |
| Table Schema                | Define the table type and the meaning of each column in the table |
| Table Runtime               | The runtime of each table in memory which is used for scanning |
| Maat State                  | Store intermediate state of multiple scans |
| Maat Stream                 | Handle of streaming file scanning |
| Hit Path                    | From the perspective of data to be scanned, describe the hit ID sequence: item_id -> sub_group_id -> superior_group_id(virtual_table_id) -> compile_id |
| Redis                       | In-memory data store，see https://redis.io/. It has a leader follower replication to ensure the high availability of rules |