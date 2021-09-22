package nlu.fit.cellphoneapp.controllers.admin;

import nlu.fit.cellphoneapp.DTOs.BrandDTO;
import nlu.fit.cellphoneapp.DTOs.TagAttrDTO;
import nlu.fit.cellphoneapp.entities.Brand;
import nlu.fit.cellphoneapp.entities.Pin;
import nlu.fit.cellphoneapp.entities.Ram;
import nlu.fit.cellphoneapp.entities.Rom;
import nlu.fit.cellphoneapp.services.IBrandService;
import nlu.fit.cellphoneapp.services.IPinService;
import nlu.fit.cellphoneapp.services.IRamService;
import nlu.fit.cellphoneapp.services.IRomService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Base64;

@Controller("adminTagsManagement")
@RequestMapping("/admin/tags-manage")
public class TagsController {

    @Autowired
    IBrandService brandService;
    @Autowired
    IRamService ramService;
    @Autowired
    IRomService romService;
    @Autowired
    IPinService pinService;

    @GetMapping("brands")
    public ModelAndView brandsPageManagement(@ModelAttribute BrandDTO brandDTO) {
        ModelAndView mv = new ModelAndView("admin/admin-brand-tag-management");
        mv.addObject("brands", brandService.findAll());
        return mv;
    }

    @GetMapping("rams")
    public ModelAndView ramsPageManagement() {
        ModelAndView mv = new ModelAndView("admin/admin-ram-tag-management");
        mv.addObject("rams", ramService.findAll());
        return mv;
    }

    @GetMapping("roms")
    public ModelAndView romsPageManagement() {
        ModelAndView mv = new ModelAndView("admin/admin-rom-tag-management");
        mv.addObject("roms", romService.findAll());
        return mv;
    }

    @GetMapping("pins")
    public ModelAndView pinsPageManagement() {
        ModelAndView mv = new ModelAndView("admin/admin-pin-tag-management");
        mv.addObject("pins", pinService.findAll());
        return mv;
    }

    //edit and delete
    @DeleteMapping("brands/{id}")
    @ResponseBody
    public String deleteATag(@PathVariable int id) {
        if (null == brandService.findOneById(id)) return "fail";
        Brand brand = (Brand) brandService.findOneById(id);
        if (brand.getActive() == 1) {
            brand.setActive(-1);
        } else {
            brand.setActive(1);
        }
        brandService.save(brand);
        return "success";
    }

    @DeleteMapping("rams/{id}")
    @ResponseBody
    public String deleteATagRam(@PathVariable int id) {
        if (null == ramService.findOneById(id)) return "fail";
        Ram ram = (Ram) ramService.findOneById(id);
        if (ram.getActive() == 1) {
            ram.setActive(-1);
        } else {
            ram.setActive(1);
        }
        ramService.save(ram);
        return "success";
    }

    @DeleteMapping("roms/{id}")
    @ResponseBody
    public String deleteATagRom(@PathVariable int id) {
        if (null == romService.findOneById(id)) return "fail";
        Rom rom = (Rom) romService.findOneById(id);
        if (rom.getActive() == 1) {
            rom.setActive(-1);
        } else {
            rom.setActive(1);
        }
        romService.save(rom);
        return "success";
    }

    @DeleteMapping("pins/{id}")
    @ResponseBody
    public String deleteATagPin(@PathVariable int id) {
        if (null == romService.findOneById(id)) return "fail";
        Pin pin = (Pin) pinService.findOneById(id);
        if (pin.getActive() == 1) {
            pin.setActive(-1);
        } else {
            pin.setActive(1);
        }
        pinService.save(pin);
        return "success";
    }

    //add new tags
    //add a new brand
    @PostMapping("brands/new")
    public String createdNewBrand(@Valid BrandDTO brandDTO, BindingResult result) throws IOException {
        if (result.hasErrors()) {
            return "admin/admin-brand-tag-management";//show error by validator on views
        }
        Brand newBrand = brandDTO.toBrandEntity();
        newBrand.setLogo(Base64.getEncoder().encodeToString(brandDTO.getLogo().getBytes()));
        brandService.save(newBrand);
        return "redirect:/admin/tags-manage/brands";
    }

    //add a new rams, roms, pins
    @PostMapping("tags/new")//pending
    @ResponseBody
    public String createNewTags(@RequestBody TagAttrDTO tagDTO){
        switch (tagDTO.getName()) {
            case "rams":
                ramService.save(new Ram().updateInfo(tagDTO));//saved into db
                break;
            case "roms":
                romService.save(new Rom().updateInfo(tagDTO));//saved into db
                break;
            case "pins":
                pinService.save(new Pin().updateInfo(tagDTO));///saved into db
                break;
        }
        return "success";
    }

    //edit a brand
    @PutMapping("brands/{id}")//okay
    @ResponseBody
    public String editBrands(@PathVariable int id, BrandDTO brandEdited) throws IOException {
        Brand brand;
        if (null == (brand = brandService.findOneById(id))) return "fail";//fail to put id brands
        Brand brandAfterEdit = brandEdited.toBrandEntity();
        brandAfterEdit.setLogo(Base64.getEncoder().encodeToString(brandEdited.getLogo().getBytes()));
        brandAfterEdit.setId(brand.getId());
        ///saved into db
        brandService.save(brandAfterEdit);
        return "success";
    }

    //edit a ram,rom,pin
    @PutMapping("{name}/{id}")//okay
    @ResponseBody
    public String editTags(@PathVariable String name, @PathVariable int id, @RequestBody TagAttrDTO tagDTO) {
        switch (name) {
            case "rams":
                Ram ram = ramService.findOneById(id);
                if (!isExisted(ram)) return "fail";
                Ram ramAfterEdited = ram.updateInfo(tagDTO);
                ramService.updateRam(id, ramAfterEdited);//saved into db
                break;
            case "roms":
                Rom rom = romService.findOneById(id);
                if (!isExisted(rom)) return "fail";
                Rom romAfterEdited = rom.updateInfo(tagDTO);
                romService.updateRom(id, romAfterEdited);//saved into db
                break;
            case "pins":
                Pin pin = pinService.findOneById(id);
                if (!isExisted(pin)) return "fail";
                Pin pinAfterEdited = pin.updateInfo(tagDTO);
                pinService.updatePin(id, pinAfterEdited);//saved into db
                break;
        }
        return "success";
    }

    private boolean isExisted(Object obj) {
        if (obj != null) return true;
        return false;
    }


}
