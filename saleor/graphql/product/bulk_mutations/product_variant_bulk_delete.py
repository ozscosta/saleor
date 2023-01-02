from typing import Iterable

import graphene
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Exists, OuterRef, Subquery
from django.db.models.fields import IntegerField
from django.db.models.functions import Coalesce

from ....attribute import AttributeInputType
from ....attribute import models as attribute_models
from ....core.permissions import ProductPermissions
from ....core.postgres import FlatConcatSearchVector
from ....core.tracing import traced_atomic_transaction
from ....order import events as order_events
from ....order import models as order_models
from ....order.tasks import recalculate_orders_task
from ....product import models
from ....product.error_codes import ProductErrorCode
from ....product.search import prepare_product_search_vector_value
from ...app.dataloaders import load_app
from ...core.descriptions import ADDED_IN_38
from ...core.mutations import ModelBulkDeleteMutation
from ...core.types import NonNullList, ProductError
from ...core.validators import validate_one_of_args_is_in_mutation
from ...plugins.dataloaders import load_plugin_manager
from ..types import ProductVariant
from ..utils import get_draft_order_lines_data_for_variants


class ProductVariantBulkDelete(ModelBulkDeleteMutation):
    class Arguments:
        ids = NonNullList(
            graphene.ID,
            required=False,
            description="List of product variant IDs to delete.",
        )
        skus = NonNullList(
            graphene.String,
            required=False,
            description="List of product variant SKUs to delete." + ADDED_IN_38,
        )

    class Meta:
        description = "Deletes product variants."
        model = models.ProductVariant
        object_type = ProductVariant
        permissions = (ProductPermissions.MANAGE_PRODUCTS,)
        error_type_class = ProductError
        error_type_field = "product_errors"

    @classmethod
    @traced_atomic_transaction()
    def perform_mutation(cls, _root, info, ids=None, skus=None, **data):
        validate_one_of_args_is_in_mutation(ProductErrorCode, "skus", skus, "ids", ids)

        if ids:
            try:
                pks = cls.get_global_ids_or_error(ids, ProductVariant)
            except ValidationError as error:
                return 0, error
        if skus:
            pks = models.ProductVariant.objects.filter(sku__in=skus).values_list(
                "pk", flat=True
            )
            ids = [graphene.Node.to_global_id("ProductVariant", pk) for pk in pks]

        draft_order_lines_data = get_draft_order_lines_data_for_variants(pks)

        product_pks = list(
            models.Product.objects.filter(variants__in=pks)
            .distinct()
            .values_list("pk", flat=True)
        )

        # Get cached variants with related fields to fully populate webhook payload.
        variants = list(
            models.ProductVariant.objects.filter(id__in=pks).prefetch_related(
                "channel_listings",
                "attributes__values",
                "variant_media",
            )
        )

        cls.delete_assigned_attribute_values(pks)
        cls.delete_product_channel_listings_without_available_variants(product_pks, pks)
        response = super().perform_mutation(_root, info, ids, **data)
        manager = load_plugin_manager(info.context)
        transaction.on_commit(
            lambda: [manager.product_variant_deleted(variant) for variant in variants]
        )

        # delete order lines for deleted variants
        order_models.OrderLine.objects.filter(
            pk__in=draft_order_lines_data.line_pks
        ).delete()

        app = load_app(info.context)
        # run order event for deleted lines
        for order, order_lines in draft_order_lines_data.order_to_lines_mapping.items():
            order_events.order_line_variant_removed_event(
                order, info.context.user, app, order_lines
            )

        order_pks = draft_order_lines_data.order_pks
        if order_pks:
            recalculate_orders_task.delay(list(order_pks))

        # set new product default variant if any has been removed
        products = models.Product.objects.filter(
            pk__in=product_pks, default_variant__isnull=True
        )
        for product in products:
            product.search_vector = FlatConcatSearchVector(
                *prepare_product_search_vector_value(product)
            )
            product.default_variant = product.variants.first()
            product.save(
                update_fields=[
                    "default_variant",
                    "search_vector",
                    "updated_at",
                ]
            )

        return response

    @staticmethod
    def delete_assigned_attribute_values(instance_pks):
        attribute_models.AttributeValue.objects.filter(
            variantassignments__variant_id__in=instance_pks,
            attribute__input_type__in=AttributeInputType.TYPES_WITH_UNIQUE_VALUES,
        ).delete()

    @staticmethod
    def delete_product_channel_listings_without_available_variants(
        product_pks: Iterable[int], variant_pks: Iterable[int]
    ):
        """Delete invalid channel listings.

        Delete product channel listings for product and channel for which
        the last available variant has been deleted.
        """
        variants = models.ProductVariant.objects.filter(
            product_id__in=product_pks
        ).exclude(id__in=variant_pks)

        variant_subquery = Subquery(
            queryset=variants.filter(id=OuterRef("variant_id")).values("product_id"),
            output_field=IntegerField(),
        )
        variant_channel_listings = models.ProductVariantChannelListing.objects.annotate(
            product_id=Coalesce(variant_subquery, 0)
        )

        invalid_product_channel_listings = models.ProductChannelListing.objects.filter(
            product_id__in=product_pks
        ).exclude(
            Exists(
                variant_channel_listings.filter(
                    channel_id=OuterRef("channel_id"), product_id=OuterRef("product_id")
                )
            )
        )
        invalid_product_channel_listings.delete()