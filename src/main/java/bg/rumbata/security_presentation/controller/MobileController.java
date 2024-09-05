package bg.rumbata.security_presentation.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cars")
public class MobileController {

    @GetMapping("/public")
    public String getPublicCars() {
        return "Public cars page! 😊😊😊";
    }

    @GetMapping("/vip")
    public String getVipCars() {
        return "Vip cars page!";
    }

    @GetMapping("/vip/header")
    public String getVipCarsHeaderAuth() {
        return "Vip cars page with header auth!";
    }

    @GetMapping("/vip/req-header")
    public String getVipCarsRequestHeaderAuth() {
        return "Vip cars page with request header auth!";
    }

    @GetMapping("/vip/jwt")
    public String getVipCarsJwtAuth() {
        return "Vip cars page with jwt auth!";
    }

    @GetMapping("/vip/oath")
    public String getVipCarsOath() {
        return "Vip cars page with oath2 auth! 😍";
    }
}
