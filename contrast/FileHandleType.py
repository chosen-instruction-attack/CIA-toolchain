#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   FileHandleType.py
@Time    :   2021/03/12 18:02:15
@Author  :   Spook3r 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

# html template file directory
templatePath = "./template_files/"

class InsLine(object):
    """
    Instruction information
    """
    def __init__(self, instruction: list):
        self.index, self.address, self.mnemonic, self.op_str = instruction
        self.type = "garbage"

class Contrast(object):
    """
    Contrast Intermediate information
    """
    # amount of instructions recovered successfully
    recovery = None
    # amount of instructions of a sliced result
    total = None
    # amount of instructions between anchors (remove instructions beyond anchors)
    reduced = None
    # redundancy rate in total
    redun_T = None
    # redundancy rate reduced
    redun_R = None
    # recovery rate
    rate = None

class DataLine(object):
    """
    Contrast result for an instruction
    """
    # amount of instructions for core operation
    valid_amount = None
    # amount of instructions in a kernel list
    kernel_amount = None
    # simulation result of symbolic execution
    simulation_result = False
    # contrast for Deobfuscator
    deobf = Contrast()
    # contrast for VMhunt
    vmhunt = Contrast()

INITIAL_HTML_TEMPLATE = """
<html>
<head>
<title>Report of {filename}</title>
<link rel="stylesheet" href="{template}basic.css" type="text/css"/>
<script type="text/javascript" src="{template}func.js"></script>
</head>
<body>
<div class="information">
<table>
    <tr>
        <th>Filename:</th>
        <th>{filename}</th>
    </tr>
    <tr>
        <th>Instruction:</th>
        <th>{ins}</th>
    </tr>
</table>
</div>
<div class="ins_title">
    <label>colored trace:</label>
    <select id="type">
        <option value=0 selected="selected">kernel</option>
        <option value=1 >transfer</option>
        <option value=2>garbage</option>
    </select>
    <button type="button" onclick="jumptoIns()">jump to</button>
</div>
<div class="ins_part">
<p id="ins_list"><span>
"""

# func.js
FUNC_JS = """
var index = 0;
var pre_type = 0;
var snippet_list = [document.getElementsByClassName("kernel"), document.getElementsByClassName("transfer"), document.getElementsByClassName("garbage")];

function jumptoIns(){
    let type = document.getElementById("type");
    let max_top = (document.getElementsByTagName("br").length - 30) * 21;

    if(type.value != pre_type){
        index = 0;
    }
    let tmp = snippet_list[type.value];
    if(tmp.length == 0){
        document.getElementById('ins_list').scrollTop = 0;
        index = 0;
        return;
    }
    let pos = tmp[index % tmp.length].offsetTop - document.getElementById('ins_list').offsetTop;
    if(pos>max_top){
        document.getElementById('ins_list').scrollTop = max_top;
        index = 0;
    }else{
        document.getElementById('ins_list').scrollTop = pos;
        index++;
    }
    pre_type = type.value;
}
"""

# basic.css
BASIC_CSS = """
.kernel
{
    background-color: #ffff00;
}
.transfer
{
    background-color: #09e6ee;
}
.garbage
{
    background-color: #8d8b8b;
}
.information
{
	margin-left: 50px;
    font-weight:bold;
    text-align: center;
}
.information th{
	font-size: 20px;
	text-align: left;
    width: 130px;
}
.ins_part{
	margin-left: 50px;
	margin-top: 5px;
	border-style:solid;
    border-color:#c4c7bd;
	border-width: 0.5px;
	width: 600px;
}
.ins_part p{
	margin: 0px;
	max-height: 609px;
	overflow: auto;
}
.ins_title
{
	margin-left: 50px;
	margin-top: 20px;
	width: 600px;
	display: flex;
	justify-content: flex-start;
    font-size: 18px;
    font-weight:bold;
}
.ins_title label{
	margin-right: auto;
}
.ins_title select{
	font-size: 16px;
	height: auto;
	width: 100px;
	margin-right: 20px;
}
.ins_title button{
	font-size: 16px;
	height: auto;
	width: 80px;
	text-align: center;
	background-color: #97a0a7;
	border-width:0.5px;
}
.ins_title button:hover{
	background-color: #ccdde7;
}
.ins_title button:active{
	background: #595e61;
}
.instructions
{
    font-size: 16px;
    line-height: 1.4em;
}
.simulation
{
	margin-left: 50px;
    font-size: 18px;
}
"""
