import os
import tree_sitter_python
from tree_sitter import Language, Parser

def get_python_parser():
    # Initialize the Tree-sitter parser for Python
    language = Language(tree_sitter_python.language())
    parser = Parser(language)
    return parser

def find_enclosing_function_or_class(node, line_number):
    """
    Finds the function or class definition node that contains the given line number.
    Tree-sitter line numbers are 0-indexed.
    """
    if node.start_point[0] <= line_number <= node.end_point[0]:
        # If it's a function or class, we might have found our target,
        # but we should check children to find the most specific enclosing one.
        target = None
        if node.type in ('function_definition', 'class_definition'):
            target = node
        
        for child in node.children:
            child_target = find_enclosing_function_or_class(child, line_number)
            if child_target:
                return child_target
        
        return target
    return None

def get_node_name(node, source_code):
    """
    Extracts the name of the function or class node.
    """
    for child in node.children:
        if child.type == 'identifier':
            return source_code[child.start_byte:child.end_byte].decode('utf-8')
    return None

def count_calls_in_file(parser, filepath, target_name):
    """
    Counts how many times 'target_name' is used as a call identifier in a given file.
    """
    try:
        with open(filepath, 'rb') as f:
            source_code = f.read()
    except Exception:
        return 0

    tree = parser.parse(source_code)
    
    # Simple traversal to find calls
    def count_calls(node):
        count = 0
        if node.type == 'call':
            # The first child is usually the function being called (can be an identifier or attribute)
            func_node = node.children[0]
            if func_node.type == 'identifier':
                name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                if name == target_name:
                    count += 1
            elif func_node.type == 'attribute':
                # e.g., obj.method()
                attr_node = func_node.children[-1] # The last child is the attribute name
                if attr_node.type == 'identifier':
                    name = source_code[attr_node.start_byte:attr_node.end_byte].decode('utf-8')
                    if name == target_name:
                        count += 1
        
        for child in node.children:
            count += count_calls(child)
        return count

    return count_calls(tree.root_node)

def compute_reachability(finding, target_dir):
    """
    Computes a reachability score based on whether the vulnerable function
    is called elsewhere in the codebase.
    """
    filepath = finding.get("file")
    line = finding.get("line")
    
    if not filepath or not line:
        return 0.0

    if os.path.isfile(target_dir):
        full_path = target_dir
    else:
        full_path = os.path.join(target_dir, filepath)
        if not os.path.exists(full_path):
            # We might have an absolute path or something else
            if os.path.exists(filepath):
                full_path = filepath
            else:
                return 0.0
            
    # For Milestone 1, we focus on Python reachability
    if not full_path.endswith('.py'):
        return 0.5 # Default score for non-Python for now

    parser = get_python_parser()
    try:
        with open(full_path, 'rb') as f:
            source_code = f.read()
    except Exception:
        return 0.0

    tree = parser.parse(source_code)
    # line in finding is 1-indexed, tree-sitter is 0-indexed
    target_node = find_enclosing_function_or_class(tree.root_node, line - 1)
    
    if not target_node:
        # Not inside a function/class. It might be global scope, which is always reachable.
        return 1.0
        
    target_name = get_node_name(target_node, source_code)
    if not target_name:
        return 0.5 # Unknown name

    total_calls = 0
    files_with_calls = 0

    if os.path.isfile(target_dir):
        files_to_scan = [target_dir]
    else:
        files_to_scan = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in ['.git', 'venv', 'env', '__pycache__', 'node_modules', '.vscode']]
            for f in files:
                if f.endswith('.py'):
                    files_to_scan.append(os.path.join(root, f))
            
    for p in files_to_scan:
        # Don't count calls in the file where it's defined to avoid self-recursion inflating the score
        # Though in reality, local calls do matter, let's just count all for simplicity
        calls = count_calls_in_file(parser, p, target_name)
        if calls > 0:
            total_calls += calls
            if p != full_path:
                files_with_calls += 1

    # Calculate score
    # 0.2 base if it's in a function but not called anywhere.
    # +0.3 if it's called at least once
    # + up to 0.5 based on how many places it's called
    score = 0.2
    if total_calls > 0:
        score += 0.3
        # scale up to 0.5 more
        score += min(0.5, (total_calls * 0.1) + (files_with_calls * 0.1))
        
    return min(1.0, score)

def enhance_findings_with_risk(findings, target_dir):
    """
    Takes raw semgrep findings, calculates reachability, and computes the final risk score.
    """
    for finding in findings:
        reachability = compute_reachability(finding, target_dir)
        severity_score = finding.get("severity_score", 0.1)
        
        # Risk is a combination of severity and reachability (0 to 100)
        # If reachability <= 0.2 (0 calls detected across codebase),
        # the code is uncalled dead code; cap its risk at 35 (< 40 threshold)
        if reachability <= 0.2:
            risk_score = min(35, int((severity_score * 0.3 + reachability * 0.5) * 100))
        else:
            risk_score = int((severity_score * 0.6 + reachability * 0.4) * 100)
        
        finding["reachability"] = reachability
        finding["risk_score"] = risk_score
        
    # Sort by risk score descending
    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return findings
