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
            $bind = array(
                "ip" => $host
            );
            $response = get_web_json(
                get_web_binded_url("https://api.shodan.io/shodan/host/:ip", $bind), "get.cache", array(
                    "api" => $apikey
                )
            );
        }

        return $response;
    }
}

if(!check_function_exists("vtapi_get_report")) {
    function vtapi_get_report($resource, $apikey="") {
        $response = false;

        $config = get_config();
        $apikey = get_value_in_array("vtapi_apikey", $config, "");

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

if(!check_function_exists("openalpr_recognize")) {
    function openalpr_recognize($image, $country="us") {
        $response = false;

        $config = get_config();
        $secretkey = get_value_in_array("openalpr_secretkey", $config, "");

        $response = get_web_json(get_web_build_qs("https://api.openalpr.com/v2/recognize", array(
            "recognize_vehicle" => 1,
            "country" => $country,
            "secret_key" => $secretkey,
        )), "post.cmd.cache", array(
            "image" => "@" . $image,
        ));

        return $response;
    }
}
