<?php
// @name inteli.api.php
// @author Go Namhyeon <gnh1201@gmail.com>
// @based ReasonableFramework - https://github.com/gnh1201/reasonableframework

if(!check_function_exists("shodan_search_by_host")) {
    function shodan_search_by_host($host, $apikey="") {
        $response = false;

        $config = get_config();
        $apikey = get_value_in_array("shodan_apikey", $config, "");

        if(loadHelper("webpagetool")) {
            $response = get_web_json(
                sprintf("https://api.shodan.io/shodan/host/%s", $host), "get.cache", array(
                    "api" => $apikey
                )
            );
        }

        return $response;
    }
}

if(!check_function_exists("virustotal_get_report")) {
    function vtapi_get_file_report($resource, $apikey="") {
        $response = false;

        $config = get_config();
        $apikey = get_value_in_array("virustotal_apikey", $config, "");

        if(loadHelper("webpagetool")) {
            $response = get_web_json(
                "https://www.virustotal.com/vtapi/v2/file/report", "get.cache", array(
                    "apikey" => $apikey,
                    "resource" => $resource
                )
            );
        }

        return $response;
    }
}
~                                                                                                                                                                                                                                                                              
~                                                                                                                                                                                                                                                                              
~                                                                                                                                                                                                                                                                              
~               
