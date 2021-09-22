package nlu.fit.cellphoneapp.controllers.admin;

import nlu.fit.cellphoneapp.DTOs.ProductDTO;
import nlu.fit.cellphoneapp.converters.ImageAddress;
import nlu.fit.cellphoneapp.converters.ImageAddressConventer;
import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.helper.UploadFileHelper;
import nlu.fit.cellphoneapp.others.Link;
import nlu.fit.cellphoneapp.receiver.JSONFileUpload;
import nlu.fit.cellphoneapp.services.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.multipart.MultipartFile;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;

import javax.servlet.ServletContext;
import java.io.File;
import java.io.IOException;
import java.util.Base64;

@Controller("adminProductController")
@RequestMapping("/admin/products-manage")
public class ProductController implements ServletContextAware {
    private ServletContext context;
    @Autowired
    private IProductService productService;
    @Autowired
    private IBrandService brandService;
    @Autowired
    private IRamService ramService;
    @Autowired
    private IRomService romService;
    @Autowired
    private IPinService pinService;

    @GetMapping
    public String goToProductManagement(@RequestParam(value = "page", required = false, defaultValue = "1") int page, @RequestParam(value = "find", required = false, defaultValue = "") String find, Model model){
        Page<Product> productPage = productService.findPaginated(page, 10);
        if(find !="" || find != null || !find.equals("")){
            Specification<Product> spec = Specification.where(productService.getProductByName(find));
            Pageable pageable = PageRequest.of(page - 1, 10);
            productPage  = productService.getPage(spec, pageable);
            model.addAttribute("listProduct", productPage.getContent());
            model.addAttribute("find", find);
        }else {
            model.addAttribute("listProduct", productPage.getContent());
        }
        model.addAttribute("sumProductsAmount", productService.findAll().size());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", productPage.getTotalPages());
        model.addAttribute("totalRecords", productPage.getTotalElements());
        model.addAttribute("productInfo", new ProductDTO());
        model.addAttribute("allBrands", brandService.findAllByActive(1));
        model.addAttribute("allRams", ramService.findAllByActive(1));
        model.addAttribute("allRoms", romService.findAllByActive(1));
        model.addAttribute("allPins", pinService.findAllByActive(1));
        return "admin/admin-product-managerment";
    }

    @PutMapping("/{id}")
    public String updateProductInfo(int id) {
        if(null == productService.findOneByID(id)) return "error";

        Product oldProduct = productService.findOneByID(id);

        //update
        return "";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.context = servletContext;
    }

    @RequestMapping(value = "upload_ckeditor", method = RequestMethod.POST, produces = {MimeTypeUtils.APPLICATION_JSON_VALUE})
    public ResponseEntity<JSONFileUpload> uploadByCKEditor(@RequestParam("upload") MultipartFile upload){
        try{
            String fileName = UploadFileHelper.upload(upload, context);
            System.out.println("file name upload = "+fileName);
            return new ResponseEntity<>(new JSONFileUpload("/images/"+fileName),HttpStatus.OK);
        }catch (Exception e){
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
    @RequestMapping(value = "filebrowser", method = RequestMethod.GET)
    public String fileBrowser(ModelMap modelMap){
        File folder = new File(context.getRealPath("/images/"));
        modelMap.put("files", folder.listFiles());
        return "admin/images-upload";
    }

    @PostMapping("new")
    public String createNewProduct(ProductDTO product) throws IOException {
        //convert to entities
        Product productEntity = product.toProductEntity();
        ImageAddress imgAddress = new ImageAddressConventer().convertToEntityAttribute("img/sanpham/samsung/note10/1.jpg");
        productEntity.setImg(new ImageAddress(Link.HOST, Base64.getEncoder().encodeToString(product.getImg().getBytes())));;
        productEntity.setBrand(brandService.findOneById(product.getBrandID()));
        productEntity.setRam(ramService.findOneById(product.getRamID()));
        productEntity.setRom(romService.findOneById(product.getRomID()));
        productEntity.setPin(pinService.findOneById(product.getPinID()));
        productEntity.setImg01(new ImageAddress(Link.HOST, product.getImg01()!=null?Base64.getEncoder().encodeToString(product.getImg01().getBytes()):""));
        productEntity.setImg02(new ImageAddress(Link.HOST, product.getImg02()!=null?Base64.getEncoder().encodeToString(product.getImg02().getBytes()):""));
        productEntity.setImg03(new ImageAddress(Link.HOST, product.getImg03()!=null?Base64.getEncoder().encodeToString(product.getImg03().getBytes()):""));
        productEntity.setImg04(new ImageAddress(Link.HOST, product.getImg04()!=null?Base64.getEncoder().encodeToString(product.getImg04().getBytes()):""));

        productEntity.setLongDescription(product.getLongDescription());
        if(null == productService.insertIntoTable(productEntity)) return "error";
        return "redirect:/admin/products-manage";
    }

    @DeleteMapping("/{id}")
    @ResponseBody
    public String removeProduct(@PathVariable int id){
        productService.deleteOneById(id);
        return "success";
    }


}

