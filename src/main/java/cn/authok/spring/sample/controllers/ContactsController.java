package cn.authok.spring.sample.controllers;

import cn.authok.spring.sample.models.Contact;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/contacts")
public class ContactsController {

    @GetMapping("/{id}")
    public Contact retrieve(@PathVariable("id") String id) {
        Contact contact = new Contact();
        contact.setName("张三");
        return contact;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public void create(@RequestBody Contact contact) {
        // TODO save
    }
}
