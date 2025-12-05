/*
   Copyright Farcloser.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package buildkit

import (
	"fmt"
)

func colors() string {
	/*
		fromEnv := os.Getenv("FARCLOSER_COLORS")
		if fromEnv == "" {
			solarDark()

			fromEnv = solarToBk()
		}

		const n = 20
		builder := aec.EmptyBuilder

		up2 := aec.Up(2)
		col := aec.Column(n + 2)
		bar := aec.Color8BitF(aec.NewRGB8Bit(64, 255, 64))
		label := builder.CyanB().LightRedF().Underline().With(col).Right(1).ANSI

		// for up2
		fmt.Println()
		fmt.Println()

		for i := 0; i <= n; i++ {
			fmt.Print(up2)
			fmt.Println(label.Apply(fmt.Sprint(i, "/", n)))
			fmt.Print("[")
			fmt.Print(bar.Apply(strings.Repeat("=", i)))
			fmt.Println(col.Apply("]"))
			time.Sleep(100 * time.Millisecond)
		}

	*/ //nolint:dupword
	return solarToBk()
}

func solarToBk() string {
	return fmt.Sprintf("run=%s:warning=%s:error=%s:cancel=%s", solViolet, solOrange, solRed, solMagenta)
}

const (
	solOrange  = "203,75,22"
	solRed     = "220,50,47"
	solMagenta = "211,54,130"
	solViolet  = "108,113,196"
)

/*
const (
        solBase03  = "0,43,54"
        solBase02  = "7,54,66"
        solBase01  = "88,110,117"
        solBase00  = "101,123,131"
        solBase0   = "131,148,150"
        solBase1   = "147,161,161"
        solBase2   = "238,232,213"
        solBase3   = "253,246,227"
        solYellow  = "181,137,0".
        solBlue    = "38,139,210"
        solCyan    = "42,161,152"
        solGreen   = "133,153,0"
)

var (
	solEmphasize            string
	solComments             string
	solBackgroundHighlights string
	solBackground           string
	solError                string
	solWarning              string
	solInfo                 string
	solDebug                string
	solBodyText             string
)

func solarDark() {
	solBodyText = solBase0
	solEmphasize = solBase1
	solComments = solBase01
	solBackgroundHighlights = solBase02
	solBackground = solBase03
	solError = solRed
	solWarning = solOrange
	solInfo = solGreen
	solDebug = solBodyText
}

// Alternative color schema (light version).
func solarLight() {
	solBodyText = solBase00
	solEmphasize = solBase01
	solComments = solBase1
	solBackgroundHighlights = solBase2
	solBackground = solBase3
	solError = solRed
	solWarning = solOrange
	solInfo = solGreen
	solDebug = solBodyText
}

*/

/*

#SOLARIZED HEX     16/8 TERMCOL  XTERM/HEX   L*A*B      RGB         HSB
#--------- ------- ---- -------  ----------- ---------- ----------- -----------
#base03    #002b36  8/4 brblack  234 #1c1c1c 15 -12 -12     0  43  54 193 100  21
#base02    #073642  0/4 black    235 #262626 20 -12 -12     7  54  66 192  90  26
#base01    #586e75 10/7 brgreen  240 #585858 45 -07 -07    88 110 117 194  25  46
#base00    #657b83 11/7 bryellow 241 #626262 50 -07 -07   101 123 131 195  23  51
#base0     #839496 12/6 brblue   244 #808080 60 -06 -03   131 148 150 186  13  59
#base1     #93a1a1 14/4 brcyan   245 #8a8a8a 65 -05 -02   147 161 161 180   9  63
#base2     #eee8d5  7/7 white    254 #e4e4e4 92 -00  10   238 232 213  44  11  93
#base3     #fdf6e3 15/7 brwhite  230 #ffffd7 97  00  10   253 246 227  44  10  99

#yellow    #b58900  3/3 yellow   136 #af8700 60  10  65   181 137   0  45 100  71
#orange    #cb4b16  9/3 brred    166 #d75f00 50  50  55   203  75  22  18  89  80
#red       #dc322f  1/1 red      160 #d70000 50  65  45   220  50  47   1  79  86
#magenta   #d33682  5/5 magenta  125 #af005f 50  65 -05   211  54 130 331  74  83
#violet    #6c71c4 13/5 brmagenta 61 #5f5faf 50  15 -45   108 113 196 237  45  77
#blue      #268bd2  4/4 blue      33 #0087ff 55 -10 -45    38 139 210 205  82  82
#cyan      #2aa198  6/6 cyan      37 #00afaf 60 -35 -05    42 161 152 175  74  63
#green     #859900  2/2 green     64 #5f8700 60 -20  65   133 153   0  68 100  60
*/
