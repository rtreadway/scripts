create table #edlvl_to_grade as
select '2'  ed_lvl, 'eighth'           grade union
select '4', 'ninth'            union
select '5', 'tenth'            union
select '6', 'eleventh'         union
select '7', 'twelfth'          union
select '10', 'no_response'     union
select '11', 'unknown'         union
select '14', 'sixth'           union
select '15', 'seventh'         union
select '22', 'prekindergarten' union
select '23', 'kindergarten'    union
select '24', 'first'           union
select '25', 'second'          union
select '26', 'third'           union
select '27', 'fourth'          union
select '28', 'fifth'           union
select '29', 'thirteenth';