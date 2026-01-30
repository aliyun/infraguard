package funcs

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// FnCalculate evaluates a mathematical expression
// Supports: +, -, *, /, **, //, %, ()
// Fn::Calculate: "1 + 2 * 3" => 7
// Fn::Calculate: "2 ** 3" => 8
// Fn::Calculate: "7 // 2" => 3
func FnCalculate(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	resolved, err := resolveValue(value, params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::Calculate: error resolving value: %w", err)
	}

	// If still a function, can't calculate (not an error, just can't resolve statically)
	if isFunction(resolved) {
		return map[string]interface{}{"Fn::Calculate": value}, nil
	}

	expr, ok := resolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::Calculate: expression must be a string, got %T", resolved)
	}

	// Parse and evaluate the expression
	result, err := parseExpression(expr)
	if err != nil {
		// If we can't parse it (e.g., contains variables), return as-is
		return map[string]interface{}{"Fn::Calculate": value}, nil
	}

	// Return as int if it's a whole number
	if result == float64(int(result)) {
		return int(result), nil
	}
	return result, nil
}

// parseExpression is the entry point for the recursive descent parser
func parseExpression(expr string) (float64, error) {
	p := &parser{input: strings.TrimSpace(expr), pos: 0}
	result, err := p.parseAddSub()
	if err != nil {
		return 0, err
	}
	if p.pos < len(p.input) {
		return 0, fmt.Errorf("unexpected character at position %d: %c", p.pos, p.input[p.pos])
	}
	return result, nil
}

type parser struct {
	input string
	pos   int
}

// skipWhitespace skips whitespace characters
func (p *parser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

// parseAddSub handles addition and subtraction (lowest precedence)
func (p *parser) parseAddSub() (float64, error) {
	left, err := p.parseMulDivMod()
	if err != nil {
		return 0, err
	}

	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			break
		}

		op := p.input[p.pos]
		if op != '+' && op != '-' {
			break
		}
		p.pos++

		right, err := p.parseMulDivMod()
		if err != nil {
			return 0, err
		}

		if op == '+' {
			left = left + right
		} else {
			left = left - right
		}
	}

	return left, nil
}

// parseMulDivMod handles multiplication, division, floor division, and modulo
func (p *parser) parseMulDivMod() (float64, error) {
	left, err := p.parsePower()
	if err != nil {
		return 0, err
	}

	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			break
		}

		var op string
		// Check for // (floor division) and ** (power, already handled in parsePower)
		if p.pos+1 < len(p.input) && p.input[p.pos:p.pos+2] == "//" {
			op = "//"
			p.pos += 2
		} else if p.input[p.pos] == '*' || p.input[p.pos] == '/' || p.input[p.pos] == '%' {
			op = string(p.input[p.pos])
			p.pos++
		} else {
			break
		}

		right, err := p.parsePower()
		if err != nil {
			return 0, err
		}

		switch op {
		case "*":
			left = left * right
		case "/":
			if right == 0 {
				return 0, fmt.Errorf("division by zero")
			}
			left = left / right
		case "//":
			if right == 0 {
				return 0, fmt.Errorf("division by zero")
			}
			left = math.Floor(left / right)
		case "%":
			if right == 0 {
				return 0, fmt.Errorf("modulo by zero")
			}
			left = math.Mod(left, right)
		}
	}

	return left, nil
}

// parsePower handles exponentiation (highest precedence among binary operators)
func (p *parser) parsePower() (float64, error) {
	left, err := p.parseUnary()
	if err != nil {
		return 0, err
	}

	p.skipWhitespace()
	if p.pos+1 < len(p.input) && p.input[p.pos:p.pos+2] == "**" {
		p.pos += 2
		right, err := p.parsePower() // Right associative
		if err != nil {
			return 0, err
		}
		return math.Pow(left, right), nil
	}

	return left, nil
}

// parseUnary handles unary operators (+ and -)
func (p *parser) parseUnary() (float64, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return 0, fmt.Errorf("unexpected end of expression")
	}

	if p.input[p.pos] == '+' {
		p.pos++
		return p.parseUnary()
	}

	if p.input[p.pos] == '-' {
		p.pos++
		val, err := p.parseUnary()
		if err != nil {
			return 0, err
		}
		return -val, nil
	}

	return p.parsePrimary()
}

// parsePrimary handles numbers and parentheses
func (p *parser) parsePrimary() (float64, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return 0, fmt.Errorf("unexpected end of expression")
	}

	// Handle parentheses
	if p.input[p.pos] == '(' {
		p.pos++
		result, err := p.parseAddSub()
		if err != nil {
			return 0, err
		}
		p.skipWhitespace()
		if p.pos >= len(p.input) || p.input[p.pos] != ')' {
			return 0, fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return result, nil
	}

	// Parse number
	start := p.pos
	if p.input[p.pos] == '.' || unicode.IsDigit(rune(p.input[p.pos])) {
		for p.pos < len(p.input) && (unicode.IsDigit(rune(p.input[p.pos])) || p.input[p.pos] == '.') {
			p.pos++
		}
		numStr := p.input[start:p.pos]
		num, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid number: %s", numStr)
		}
		return num, nil
	}

	return 0, fmt.Errorf("unexpected character: %c", p.input[p.pos])
}
