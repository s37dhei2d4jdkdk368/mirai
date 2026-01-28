package utils

import (
	"cnc/core/config"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func ReplaceFromMap(target string, objects map[string]string) string {
	for targetValue, value := range objects {
		target = strings.ReplaceAll(target, targetValue, value)
	}
	return target
}

func ParseDuration(input string) (time.Duration, error) {
	var totalDuration time.Duration

	unitMultiplier := map[string]time.Duration{
		"d":   time.Hour * 24,
		"w":   time.Hour * 24 * 7,
		"m":   time.Hour * 24 * 30,
		"s":   time.Second,
		"min": time.Minute,
	}

	regex := regexp.MustCompile(`(\d+)([dwms]+)`)
	matches := regex.FindAllStringSubmatch(input, -1)

	for _, match := range matches {
		value, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}

		units := match[2]

		multiplier, exists := unitMultiplier[units]
		if !exists {
			return 0, fmt.Errorf("unknown time unit in %s", match[0])
		}

		totalDuration += time.Duration(value) * multiplier
	}

	return totalDuration, nil
}

type IPInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"` 
	ISP         string `json:"isp"`         
	Org         string `json:"org"`         
	Status      string `json:"status"`      
}

func GetIPInfo(ip string) (string, string) {
	if ip == "127.0.0.1" || ip == "localhost" || ip == "::1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "Localhost", "Local ISP"
	}

	
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var ipInfo IPInfo
			if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err == nil {
				if ipInfo.Status == "success" {
					if ipInfo.Country == "" && ipInfo.CountryCode != "" {
						ipInfo.Country = GetCountryName(ipInfo.CountryCode)
					}
					if ipInfo.Country != "" {
						if ipInfo.ISP == "" {
							ipInfo.ISP = "Unknown"
						}
						return ipInfo.Country, ipInfo.ISP
					}
				}
			}
		}
	}

	
	url := "https://ipinfo.io/" + ip + "/json"
	if config.Config.IpInfoToken != "" {
		url += "?token=" + config.Config.IpInfoToken
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "Unknown", "Unknown"
	}
	req.Header.Set("User-Agent", "CNC-Botnet/1.0")

	resp, err = client.Do(req)
	if err != nil {
		return "Unknown", "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown", "Unknown"
	}

	var ipInfo IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return "Unknown", "Unknown"
	}

	
	if ipInfo.Country != "" {
		ipInfo.Country = GetCountryName(ipInfo.Country)
	}

	if ipInfo.Country == "" {
		ipInfo.Country = "Unknown"
	}

	
	isp := ipInfo.Org
	if isp == "" {
		isp = "Unknown"
	}

	return ipInfo.Country, isp
}

var countryMap = map[string]string{
	"AF": "Afghanistan", "AX": "Aland Islands", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa",
	"AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda",
	"AR": "Argentina", "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria",
	"AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados",
	"BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda",
	"BT": "Bhutan", "BO": "Bolivia", "BQ": "Bonaire, Sint Eustatius and Saba", "BA": "Bosnia", "BW": "Botswana",
	"BV": "Bouvet Island", "BR": "Brazil", "IO": "British Indian Ocean Territory", "BN": "Brunei", "BG": "Bulgaria",
	"BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
	"CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile",
	"CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros",
	"CG": "Congo", "CD": "Congo, Democratic Republic of the", "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote d'Ivoire",
	"HR": "Croatia", "CU": "Cuba", "CW": "Curacao", "CY": "Cyprus", "CZ": "Czech Republic",
	"DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador",
	"EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia",
	"ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland",
	"FR": "France", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French S.T.", "GA": "Gabon",
	"GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar",
	"GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam",
	"GT": "Guatemala", "GG": "Guernsey", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana",
	"HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras", "HK": "Hong Kong",
	"HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran",
	"IQ": "Iraq", "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel", "IT": "Italy",
	"JM": "Jamaica", "JP": "Japan", "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan",
	"KE": "Kenya", "KI": "Kiribati", "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait",
	"KG": "Kyrgyzstan", "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho",
	"LR": "Liberia", "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
	"MO": "Macao", "MK": "Macedonia, the Former Yugoslav Republic of", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia",
	"MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique",
	"MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia",
	"MD": "Moldova, Republic of", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat",
	"MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru",
	"NP": "Nepal", "NL": "Netherlands", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua",
	"NE": "Niger", "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands",
	"NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestine, State of",
	"PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines",
	"PN": "Pitcairn", "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar",
	"RE": "Reunion", "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "BL": "Saint Barthelemy",
	"SH": "Saint Helena, Ascension and Tristan da Cunha", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "MF": "Saint Martin (French part)", "PM": "Saint Pierre and Miquelon",
	"VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe", "SA": "Saudi Arabia",
	"SN": "Senegal", "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
	"SX": "Sint Maarten (Dutch part)", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia",
	"ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
	"SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden",
	"CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of",
	"TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga",
	"TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands",
	"TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
	"US": "United States", "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu",
	"VE": "Venezuela, Bolivarian Republic of", "VN": "Viet Nam", "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.", "WF": "Wallis and Futuna",
	"EH": "Western Sahara", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe",
}

func GetCountryName(code string) string {
	if name, ok := countryMap[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}

func NormalizeCountryName(name string) string {
	lowerName := strings.ToLower(name)
	
	if cName, ok := countryMap[strings.ToUpper(name)]; ok {
		return cName
	}
	
	for _, v := range countryMap {
		if strings.ToLower(v) == lowerName {
			return v
		}
	}
	
	return strings.Title(lowerName)
}


func IfThenElse(condition bool, a, b string) string {
	if condition {
		return a
	}
	return b
}

func StripAnsi(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\a]*\a`)
	return re.ReplaceAllString(s, "")
}

func AnsiStringLength(s string) int {
	return utf8.RuneCountInString(StripAnsi(s))
}
